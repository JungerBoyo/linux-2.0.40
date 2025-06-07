#include <linux/module.h>

#include <asm/semaphore.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/malloc.h>
#include <linux/sched.h>

#define MAJOR_NR ZRAMDISK_MAJOR
#include <linux/blk.h>

/*
 * Module params
 */
int zrd_num_devices = 1;
int zrd_blk_size    = 1024;
int zrd_verbose_log = 0;

/*
 * Module defs and types
 */
#define ZRD_BLKSIZE_SIZE PAGE_SIZE
#define ZRD_HARDSECT_SIZE 512

#define ZRD_SECTORS_IN_BLK (ZRD_BLKSIZE_SIZE / ZRD_HARDSECT_SIZE)
#define ZRD_INITIAL_BLKSIZE_SIZE 4096
#define ZRD_HASH_TABLE_SIZE 12

#define ZRD_IO_COMPRESSION_RATE_GET _IOR(MAJOR_NR, 0, long)

struct zrd_dev {
    int nr;
    void **blocks;
    unsigned short *block_sizes;
    int size;
    void *scratch_blk;
    unsigned short *hash_table;
};

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/*
 * Module data
 */
static void *zrd_mem;
static struct zrd_dev *zrd_devs;
static int *zrd_blk_sizes;
static int *zrd_blksize_sizes;
static int *zrd_hardsect_sizes;

/*
 * Module interface
 */
static int zrd_ioctl(struct inode *inode, struct file *file, unsigned int cmd,
                     unsigned long arg);
static int zrd_open(struct inode *inode, struct file *file);
static void zrd_release(struct inode *inode, struct file *file);

static struct file_operations file_ops = {
    .lseek   = NULL,
    .read    = block_read,
    .write   = block_write,
    .readdir = NULL,
    .select  = NULL,
    .ioctl   = zrd_ioctl,
    .mmap    = NULL,
    .open    = zrd_open,
#ifndef MODULE
    .release = NULL,
#else
    .release = zrd_release,
#endif
    .fsync = block_fsync,
};

static void zrd_request(void);

/*
 * Module init
 */
int zrd_init(void)
{
    int i;
    int mem_size;

    if (zrd_num_devices < 1 || zrd_blk_size < 1) {
        printk("ZRAMDISK: num of devices and blk size must be at least 1\n");
        return -EINVAL;
    }

    mem_size = zrd_num_devices * (sizeof(struct zrd_dev) + sizeof(int) +
                                  sizeof(int) + sizeof(int));
    zrd_mem  = kmalloc(mem_size, GFP_KERNEL);
    if (zrd_mem == NULL) {
        printk("ZRAMDISK: Failed to allocate zramdisk driver metadata\n");
        return -ENOMEM;
    }

    if (register_blkdev(MAJOR_NR, "zramdisk", &file_ops)) {
        printk("ZRAMDISK: Could not get major %d\n", MAJOR_NR);
        goto err_register;
    }

    zrd_devs           = zrd_mem;
    zrd_blk_sizes      = (int *)(zrd_devs + zrd_num_devices);
    zrd_blksize_sizes  = zrd_blk_sizes + zrd_num_devices;
    zrd_hardsect_sizes = zrd_blksize_sizes + zrd_num_devices;

    for (i = 0; i < zrd_num_devices; ++i) {
        zrd_devs[i].nr          = i;
        zrd_devs[i].blocks      = NULL;
        zrd_devs[i].block_sizes = NULL;
        zrd_devs[i].size        = zrd_blk_size * ZRD_BLKSIZE_SIZE;
        zrd_blk_sizes[i]        = zrd_blk_size;
        zrd_blksize_sizes[i]    = ZRD_BLKSIZE_SIZE;
        zrd_hardsect_sizes[i]   = ZRD_HARDSECT_SIZE;
    }

    blk_dev[MAJOR_NR].request_fn = &zrd_request;
    blk_size[MAJOR_NR]           = zrd_blk_sizes;
    blksize_size[MAJOR_NR]       = zrd_blksize_sizes;
    hardsect_size[MAJOR_NR]      = zrd_hardsect_sizes;

    printk("ZRAMDISK: initialized zrd_num_devices=%d, zrd_blk_size=%d, "
           "zrd_verbose_log=%d\n",
           zrd_num_devices, zrd_blk_size, zrd_verbose_log);
    return 0;
err_register:
    kfree(zrd_mem);
    return -EIO;
}

#ifdef MODULE
int init_module(void)
{
    return zrd_init();
}

void cleanup_module(void)
{
    int i, j;

    for (i = 0; i < zrd_num_devices; ++i) {
        if (zrd_devs[i].block_sizes != NULL)
            kfree(zrd_devs[i].block_sizes);

        if (zrd_devs[i].blocks != NULL) {
            for (j = 0; j < zrd_blk_size; ++j)
                kfree(zrd_devs[i].blocks[j]);
            kfree(zrd_devs[i].blocks);
        }

        if (zrd_devs[i].scratch_blk != NULL)
            kfree(zrd_devs[i].scratch_blk);

        if (zrd_devs[i].hash_table != NULL)
            kfree(zrd_devs[i].hash_table);
    }

    kfree(zrd_mem);

    unregister_blkdev(MAJOR_NR, "zramdisk");
    blk_dev[MAJOR_NR].request_fn = NULL;

    printk("ZRAMDISK: cleaned up\n");
}
#endif

/*
 * Module utils
 */
static struct zrd_dev *get_dev(struct inode *inode)
{
    int dev_nr = MINOR(inode->i_rdev);
    if (dev_nr >= zrd_num_devices)
        return NULL;

    return zrd_devs + dev_nr;
}

/*
 * Module impl.
 */
static int zrd_ioctl(struct inode *inode, struct file *file, unsigned int cmd,
                     unsigned long arg)
{
    int i, err, valid_block_sizes, total_size;
    struct zrd_dev *dev = get_dev(inode);
    if (dev == NULL)
        return -ENXIO;

    if (zrd_verbose_log)
        printk("ZRAMDISK: ioctl cmd %d on dev %d\n", cmd, dev->nr);

    switch (cmd) {
    case ZRD_IO_COMPRESSION_RATE_GET: {
        if (!arg)
            return -EINVAL;

        err = verify_area(VERIFY_WRITE, (long *)arg, sizeof(long));
        if (err)
            return err;

        valid_block_sizes = 0;
        total_size        = 0;
        for (i = 0; i < zrd_blk_size; ++i)
            if (dev->block_sizes[i] != 0) {
                ++valid_block_sizes;
                total_size += (int)(dev->block_sizes[i]);
            }

        put_user(1000 * total_size / (valid_block_sizes * ZRD_BLKSIZE_SIZE),
                 (long *)arg);
        break;
    }
    case BLKFLSBUF: {
        if (!suser())
            return -EACCES;
        invalidate_buffers(inode->i_rdev);
        break;
    }
    case BLKGETSIZE: {
        if (!arg)
            return -EINVAL;

        err = verify_area(VERIFY_WRITE, (long *)arg, sizeof(long));
        if (err)
            return err;

        put_user((zrd_blk_size * ZRD_BLKSIZE_SIZE) / ZRD_HARDSECT_SIZE,
                 (long *)arg);
        break;
    }
    default:
        return -EINVAL;
    }
    return 0;
}
static int zrd_open(struct inode *inode, struct file *file)
{
    int i, j;
    struct zrd_dev *dev = get_dev(inode);
    if (dev == NULL)
        return -ENXIO;

    if (dev->block_sizes == NULL) {
        dev->block_sizes =
            kmalloc(zrd_blk_size * sizeof(*dev->blocks), GFP_KERNEL);
        if (dev->block_sizes == NULL) {
            printk("ZRAMDISK: Failed to allocate zramdisk %d block_sizes\n",
                   dev->nr);
            goto err_block_sizes;
        }

        dev->blocks = kmalloc(zrd_blk_size * sizeof(*dev->blocks), GFP_KERNEL);
        if (dev->blocks == NULL) {
            printk("ZRAMDISK: Failed to allocate zramdisk %d blocks\n",
                   dev->nr);
            goto err_blocks;
        }

        for (i = 0; i < zrd_blk_size; ++i) {
            dev->block_sizes[i] = ZRD_INITIAL_BLKSIZE_SIZE;
            dev->blocks[i]      = kmalloc(ZRD_INITIAL_BLKSIZE_SIZE, GFP_KERNEL);
            if (dev->blocks[i] == NULL) {
                printk("ZRAMDISK: Failed to allocate zramdisk %d block %d\n",
                       dev->nr, i);
                goto err_block;
            }
        }

        dev->scratch_blk = kmalloc(ZRD_BLKSIZE_SIZE, GFP_KERNEL);
        if (dev->scratch_blk == NULL) {
            printk("ZRAMDISK: Failed to allocate scratch blk for dev %d\n",
                   dev->nr);
            goto err_scratch;
        }

        dev->hash_table = kmalloc(
            (1 << ZRD_HASH_TABLE_SIZE) * sizeof(*dev->hash_table), GFP_KERNEL);
        if (dev->hash_table == NULL) {
            printk("ZRAMDISK: Failed to allocate hash table for dev %d\n",
                   dev->nr);
            goto err_hash_table;
        }
        memset(dev->hash_table, 0xFF,
               (1 << ZRD_HASH_TABLE_SIZE) * sizeof(*dev->hash_table));
    }

    MOD_INC_USE_COUNT;

    printk("ZRAMDISK: Opened dev %d\n", dev->nr);
    return 0;
err_hash_table:
    kfree(dev->hash_table);
    dev->hash_table = NULL;
err_scratch:
err_block:
    for (j = 0; j < i; ++j)
        kfree(dev->blocks[j]);
    kfree(dev->blocks);
    dev->blocks = NULL;
err_blocks:
    kfree(dev->block_sizes);
    dev->block_sizes = NULL;
err_block_sizes:
    return -ENOMEM;
}

static void zrd_release(struct inode *inode, struct file *file)
{
    struct zrd_dev *dev = get_dev(inode);
    if (dev == NULL)
        return;

    MOD_DEC_USE_COUNT;

    printk("ZRAMDISK: Closed dev %d\n", dev->nr);
}

static int zread(struct zrd_dev *dev, void *dst, int sector, int num_sectors);
static int zwrite(struct zrd_dev *dev, const void *src, int sector,
                  int num_sectors);

static void zrd_request(void)
{
    unsigned int minor;
    int offset, len, sector, num_sectors;
    struct zrd_dev *zrd_dev;
    void *cache_ptr;

repeat:
    INIT_REQUEST;

    minor = DEVICE_NR(CURRENT->rq_dev);

    if (minor >= zrd_num_devices) {
        printk("ZRAMDISK: dev %d invalid\n", minor);
        end_request(0);
        goto repeat;
    }

    zrd_dev = zrd_devs + minor;

    if (zrd_dev->block_sizes == NULL) {
        printk("ZRAMDISK: dev %d not opened\n", minor);
        end_request(0);
        goto repeat;
    }

    sector      = CURRENT->sector;
    num_sectors = CURRENT->current_nr_sectors;
    offset      = sector * ZRD_HARDSECT_SIZE;
    len         = num_sectors * ZRD_HARDSECT_SIZE;
    cache_ptr   = CURRENT->buffer;

    if ((offset + len) > zrd_dev->size) {
        printk("ZRAMDISK: dev %d overrun by %d bytes\n", zrd_dev->nr,
               (offset + len) - zrd_dev->size);
        end_request(0);
        goto repeat;
    }

    if (CURRENT->cmd == READ) {
        zread(zrd_dev, cache_ptr, sector, num_sectors);
        if (zrd_verbose_log)
            printk("ZRAMDISK: read [%d,%d) sectors\n", sector,
                   sector + num_sectors);
    } else if (CURRENT->cmd == WRITE) {
        zwrite(zrd_dev, cache_ptr, sector, num_sectors);
        if (zrd_verbose_log)
            printk("ZRAMDISK: wrote [%d,%d) sectors\n", sector,
                   sector + num_sectors);
    } else {
        printk("ZRAMDISK: dev %d received unknown cmd %d\n", zrd_dev->nr,
               CURRENT->cmd);
        end_request(0);
        goto repeat;
    }

    CURRENT->nr_sectors -= CURRENT->current_nr_sectors;
    end_request(1);
    goto repeat;
}

static int decompress(void *dst, const void *src, int size);
static int compress(unsigned short *hash_table, void *dst, const void *src,
                    int dst_size, int src_size);

static int zread(struct zrd_dev *dev, void *dst, int sector, int num_sectors)
{
    int block, block_start_sector, block_end_sector, i, size;
    void *blk_ptr;

    for (i = sector; i < sector + num_sectors;) {
        block              = (i * ZRD_HARDSECT_SIZE) / ZRD_BLKSIZE_SIZE;
        block_start_sector = i % ZRD_SECTORS_IN_BLK;
        block_end_sector   = MIN(ZRD_SECTORS_IN_BLK,
                                 block_start_sector + sector + num_sectors - i);
        blk_ptr            = dev->blocks[block];

        if (block_start_sector == 0 && block_end_sector == ZRD_SECTORS_IN_BLK) {
            if (decompress((char *)(dst) + (i - sector) * ZRD_HARDSECT_SIZE,
                           blk_ptr, ZRD_BLKSIZE_SIZE) != ZRD_BLKSIZE_SIZE) {
                printk("ZRAMDISK: oh, block decompressed is less than block "
                       "size?!\n");
                return 0;
            }
            i += ZRD_SECTORS_IN_BLK;
            continue;
        }

        if (decompress(dev->scratch_blk, blk_ptr, ZRD_BLKSIZE_SIZE) !=
            ZRD_BLKSIZE_SIZE) {
            printk("ZRAMDISK: oh, block decompressed is less than block "
                   "size?!\n");
            return 0;
        }

        size = (block_end_sector - block_start_sector);
        memcpy((char *)(dst) + (i - sector) * ZRD_HARDSECT_SIZE,
               (char *)(dev->scratch_blk) +
                   block_start_sector * ZRD_HARDSECT_SIZE,
               size);

        i += size;

        if (zrd_verbose_log)
            printk("ZRAMDISK: decompressed sectors [%d,%d) within block %d\n",
                   block_start_sector, block_end_sector, block);
    }

    return num_sectors * ZRD_HARDSECT_SIZE;
}

static int zwrite(struct zrd_dev *dev, const void *src, int sector,
                  int num_sectors)
{
    int block, block_start_sector, block_end_sector, i, size;
    void *blk_ptr;

    for (i = sector; i < sector + num_sectors;) {
        block              = (i * ZRD_HARDSECT_SIZE) / ZRD_BLKSIZE_SIZE;
        block_start_sector = i % ZRD_SECTORS_IN_BLK;
        block_end_sector   = MIN(ZRD_SECTORS_IN_BLK,
                                 block_start_sector + sector + num_sectors - i);
        blk_ptr            = dev->blocks[block];

        if (block_start_sector == 0 && block_end_sector == ZRD_SECTORS_IN_BLK) {
            if (compress(dev->hash_table, blk_ptr,
                         (const char *)(src) + (i - sector) * ZRD_HARDSECT_SIZE,
                         ZRD_BLKSIZE_SIZE, dev->block_sizes[block]) == 0) {
            	printk("TODO grow block if == 0 \n");
                return 0;
            }
            i += ZRD_SECTORS_IN_BLK;
            continue;
        }

        if (decompress(dev->scratch_blk, blk_ptr, ZRD_BLKSIZE_SIZE) !=
            ZRD_BLKSIZE_SIZE) {
            printk("ZRAMDISK: oh, block decompressed is less than block "
                   "size?!\n");
            return 0;
        }

        size = (block_end_sector - block_start_sector);
        memcpy((char *)(dev->scratch_blk) +
                   block_start_sector * ZRD_HARDSECT_SIZE,
               (const char *)(src) + (i - sector) * ZRD_HARDSECT_SIZE, size);

        if (compress(dev->hash_table, dev->scratch_blk, blk_ptr,
                     ZRD_BLKSIZE_SIZE, dev->block_sizes[block]) == 0) {
            printk("TODO grow block if == 0 \n");
            return 0;
        }

        if (zrd_verbose_log)
            printk("ZRAMDISK: compressed sectors [%d,%d) within block %d\n",
                   block_start_sector, block_end_sector, block);

        i += size;
    }

    return num_sectors * ZRD_HARDSECT_SIZE;
}

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int i32;

struct lz4_token {
    u8 match_len : 4;
    u8 literal_len : 4;
};

static void lz4_match_copy(u8 *dst, const u8 *src, int size)
{
    int i;
    for (i = 0; i < size; ++i)
        dst[i] = src[i];
}

static int decompress(void *dst, const void *src, int size)
{
    i32 i, literal_len, match_len, match_offset;
    u16 compressed_len = *(const u16 *)(src);
    const u8 *src_u8   = (const u8 *)(src);
    u8 *dst_u8         = (u8 *)(dst);

    for (i = sizeof(compressed_len); i < compressed_len;) {
        struct lz4_token token = *(const struct lz4_token *)(src_u8 + i);
        i += sizeof(token);

        if (token.literal_len > 0) {
            literal_len = (i32)(token.literal_len);
            if (literal_len == 0x0F) {
                for (; src_u8[i] == 0xFF; ++i)
                    literal_len += (i32)(src_u8[i]);

                literal_len += (i32)(src_u8[i]);
            }

            memcpy(dst_u8, src_u8 + i, literal_len);
            dst_u8 += literal_len;
            i += literal_len;
        }

        if (i == compressed_len)
            break; // last block, no match part present

        match_offset = (i32)(*(const u16 *)(src_u8 + i));
        i += sizeof(u16);

        match_len = (i32)(token.match_len);
        if (match_len == 0x0F) {
            for (; src_u8[i] == 0xFF; ++i)
                match_len += (i32)(src_u8[i]);

            match_len += (i32)(src_u8[i]);
        }
        match_len += 4;

        // match might overlap and depend on previously written byte!
        lz4_match_copy(dst_u8, dst_u8 - match_offset, match_len);
        dst_u8 += match_len;
    }

    return size;
}

static u32 hash(const u8 *value)
{
    u32 val = ((u32)(value[0])) | ((u32)(value[1]) << 8) |
              ((u32)(value[2]) << 16) | ((u32)(value[3]) << 24);
    return (value * 2654435761U) >> (32 - ZRD_HASH_TABLE_SIZE);
}

static int compress(unsigned short *hash_table, void *dst, const void *src,
                    int dst_size, int src_size)
{
    // TODO: add bounds checking for compressed block max size and early exits
    int i, literal_start, match_pos, literal_len, match_len;
    u32 hash_val;
    u16 match_index, match_offset, size;
    u8 *src_u8 = (u8 *)(src);
    u8 *dst_u8 = (u8 *)(dst) + 2; // first 2 bytes is dst_size
    for (i = 0, literal_start = 0; i < dst_size;) {
        hash_val    = hash(src_u8 + i);
        match_index = hash_table[hash_val];
        if (match_index == 0xFFFF) {
            hash_table[hash_val] = i++;
            continue;
        }

        match_pos = i;
        while (match_pos < dst_size &&
               src_u8[match_index++] == src_u8[match_pos++]) {
        }

        if (match_pos - i < 4)
            continue; // ouch.. overwritten by some other sequence

        struct lz4_token token = {0};

        literal_len = i - literal_start;
        if (literal_len >= 0x0F) {
            token.literal_len = 0x0F;
            literal_len -= 0x0F;

            while (literal_len >= 0xFF) {
                *(dst_u8++) = 0xFF;
                literal_len -= 0xFF;
            }

            *(dst_u8++) = literal_len;
        } else {
            token.literal_len = literal_len;
        }

        literal_len = i - literal_start;
		memcpy(dst_u8, src_u8 + literal_start, literal_len);
		dst_u8 += literal_len;

		match_offset = i - match_index;
        *(dst_u8++) = match_offset & 0xFF;
        *(dst_u8++) = match_offset >> 8;

        match_len = (match_pos - i) - 4;
        if (match_len >= 0x0F) {
            token.match_len = 0x0F;
            match_len -= 0x0F;

            while (match_len >= 0xFF) {
                *(dst_u8++) = 0xFF;
                match_len -= 0xFF;
            }

            *(dst_u8++) = match_len;
        } else {
            token.match_len = literal_len;
        }
    }

	literal_len = i - literal_start;
	if (literal_len >= 0x0F) {
		token.literal_len = 0x0F;
		literal_len -= 0x0F;

		while (literal_len >= 0xFF) {
			*(dst_u8++) = 0xFF;
			literal_len -= 0xFF;
		}

		*(dst_u8++) = literal_len;
	} else {
		token.literal_len = literal_len;
	}

	literal_len = i - literal_start;
	memcpy(dst_u8, src_u8 + literal_start, literal_len);
	dst_u8 += literal_len;

	size = dst_u8 - (u8*)(dst) - 2;
	dst_u8 = (u8*)(dst);
    *(dst_u8++) = size & 0xFF;
    *(dst_u8++) = size >> 8;

    memset(hash_table, 0xFF, (1 << ZRD_HASH_TABLE_SIZE) * dst_sizeof(u16));

    return dst_size;
}
