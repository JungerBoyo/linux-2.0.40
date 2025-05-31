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
int zrd_blk_size    = 128;

/*
 * Module defs and types
 */
#define ZRD_BLKSIZE_SIZE PAGE_SIZE
#define ZRD_HARDESC_SIZE ZRD_BLKSIZE_SIZE

#define ZRD_IO_COMPRESSION_RATE_GET _IOR(ZRAMDISK_MAJOR, 0, int)

struct zrd_dev {
    int nr;
    void *ptr;
    unsigned short *pages;
    int size;
};

/*
 * Module data
 */
static void *zrd_mem;
static struct zrd_dev *zrd_devs;
static int *zrd_blk_sizes;
static int *zrd_blksize_sizes;
static int *zrd_hardesct_sizes;

/*
 * Module interface
 */
static int zrd_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg);
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
    .fsync = NULL,
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
        printk("ZRAMDISK: num of devices and blk size must be at least 1");
        return -EINVAL;
    }

    mem_size = zrd_num_devices * (sizeof(struct zrd_dev) + sizeof(int) + sizeof(int) + sizeof(int));
    zrd_mem  = kmalloc(mem_size, GFP_KERNEL);
    if (zrd_mem == NULL) {
        printk("ZRAMDISK: Failed to allocate zramdisk driver metadata");
        return -ENOMEM;
    }

    if (register_blkdev(ZRAMDISK_MAJOR, "zramdisk", &file_ops)) {
        printk("ZRAMDISK: Could not get major %d", MAJOR_NR);
        goto err_register;
    }

    zrd_devs           = zrd_mem;
    zrd_blk_sizes      = (int *)(zrd_devs + zrd_num_devices);
    zrd_blksize_sizes  = zrd_blk_sizes + zrd_num_devices;
    zrd_hardesct_sizes = zrd_blksize_sizes + zrd_num_devices;

    for (i = 0; i < zrd_num_devices; ++i) {
        zrd_devs[i].nr        = i;
        zrd_devs[i].ptr       = NULL;
        zrd_devs[i].pages     = NULL;
        zrd_devs[i].size      = 0;
        zrd_blk_sizes[i]      = zrd_blk_size;
        zrd_blksize_sizes[i]  = ZRD_BLKSIZE_SIZE;
        zrd_hardesct_sizes[i] = ZRD_HARDESC_SIZE;
    }

    blk_dev[ZRAMDISK_MAJOR].request_fn = &zrd_request;
    blk_size[ZRAMDISK_MAJOR]           = zrd_blk_sizes;
    blksize_size[ZRAMDISK_MAJOR]       = zrd_blksize_sizes;
    hardsect_size[ZRAMDISK_MAJOR]      = zrd_hardesct_sizes;

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
    int i;

    for (i = 0; i < zrd_num_devices; ++i)
        if (zrd_devs[i].ptr != NULL)
            kfree(zrd_devs[i].ptr);

    kfree(zrd_mem);

    unregister_blkdev(ZRAMDISK_MAJOR, "zramdisk");
    blk_dev[ZRAMDISK_MAJOR].request_fn = NULL;
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
static int zrd_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
    int i, err, valid_pages, total_size;
    struct zrd_dev *dev = get_dev(inode);
    if (dev == NULL)
        return -ENXIO;

    switch (cmd) {
    case ZRD_IO_COMPRESSION_RATE_GET: {
        if (!arg)
            return -EINVAL;

        err = verify_area(VERIFY_WRITE, (long *)arg, sizeof(long));
        if (err)
            return err;

		valid_pages = 0;
		total_size = 0;
		for (i = 0; i < zrd_blk_size; ++i)
			if (dev->pages[i] != 0) {
				++valid_pages;
				total_size += (int)(dev->pages[i]);
			}

        put_user(1000 * total_size / (valid_pages * PAGE_SIZE), (long *)arg);
        break;
    }
    case BLKGETSIZE: {
        if (!arg)
            return -EINVAL;

        err = verify_area(VERIFY_WRITE, (long *)arg, sizeof(long));
        if (err)
            return err;

        put_user(dev->size / ZRD_HARDESC_SIZE, (long *)arg);
        return 0;
    }
    }
    return 0;
}
static int zrd_open(struct inode *inode, struct file *file)
{
    struct zrd_dev *dev = get_dev(inode);
    if (dev == NULL)
        return -ENXIO;

    if (dev->ptr == NULL) {
        dev->pages = kmalloc(zrd_blk_size * sizeof(*dev->pages), GFP_KERNEL);
        if (dev->pages == NULL) {
            printk("ZRAMDISK: Failed to allocate zramdisk %d metadata of size %d", dev->nr,
                   zrd_blk_size * sizeof(*dev->pages));
            return -ENOMEM;
        }
        memset((void *)dev->pages, 0, zrd_blk_size * sizeof(*dev->pages));

        dev->size = zrd_blk_size * ZRD_BLKSIZE_SIZE;
        dev->ptr  = vmalloc(dev->size);
        if (dev->ptr == NULL) {
            printk("ZRAMDISK: Failed to allocate zramdisk %d of size %d", dev->nr, dev->size);
            return -ENOMEM;
        }
    }

    MOD_INC_USE_COUNT;

    printk("ZRAMDISK: Opened dev %d", dev->nr);
    return 0;
}
static void zrd_release(struct inode *inode, struct file *file)
{
    struct zrd_dev *dev = get_dev(inode);
    if (dev->ptr != NULL)
        kfree(dev->ptr);

    MOD_DEC_USE_COUNT;

    printk("ZRAMDISK: Closed dev %d", dev->nr);
}

static int decompress(void *dst, const void *src, int size);
static int compress(void *dst, const void *src, int size);

static void zrd_request(void)
{
    unsigned int minor;
    int i, offset, len, page, num_pages, compressed_len;
    struct zrd_dev *zrd_dev;
    void *dev_ptr;
    void *cache_ptr;

repeat:
    INIT_REQUEST;

    minor = DEVICE_NR(CURRENT->rq_dev);

    if (minor >= zrd_num_devices) {
        printk("ZRAMDISK: dev %d invalid", minor);
        end_request(0);
        goto repeat;
    }

    zrd_dev = zrd_devs + minor;

    if (zrd_dev->ptr == NULL) {
        printk("ZRAMDISK: dev %d not opened", minor);
        end_request(0);
        goto repeat;
    }

    page      = CURRENT->sector;
    num_pages = CURRENT->current_nr_sectors;
    offset    = page * PAGE_SIZE;
    len       = num_pages * PAGE_SIZE;
    dev_ptr   = (char *)(zrd_dev->ptr) + page * PAGE_SIZE;
    cache_ptr = CURRENT->buffer;

    if ((offset + len) > zrd_dev->size) {
        printk("ZRAMDISK: dev %d overrun by %d bytes", zrd_dev->nr, (offset + len) - zrd_dev->size);
        end_request(0);
        goto repeat;
    }

    if (CURRENT->cmd == READ) {
        for (i = 0; i < num_pages; ++i)
            if (decompress((char *)(cache_ptr) + i * PAGE_SIZE, (char *)(dev_ptr) + i * PAGE_SIZE,
                           PAGE_SIZE) != PAGE_SIZE) {
                printk("ZRAMDISK: oh, page decompressed is less than page size?!");
                end_request(0);
                goto repeat;
            }
    } else if (CURRENT->cmd == WRITE) {
        for (i = 0; i < num_pages; ++i)
            zrd_dev->pages[page + i] = compress((char *)(dev_ptr) + i * PAGE_SIZE,
                                                (char *)(cache_ptr) + i * PAGE_SIZE, PAGE_SIZE);
    } else {
        printk("ZRAMDISK: dev %d received unknown cmd %d", zrd_dev->nr, CURRENT->cmd);
        end_request(0);
        goto repeat;
    }

    CURRENT->nr_sectors -= CURRENT->current_nr_sectors;
    end_request(1);
    goto repeat;
}

static int decompress(void *dst, const void *src, int size)
{
	memcpy(dst, src, size);
	return size;
}
static int compress(void *dst, const void *src, int size)
{
	memcpy(dst, src, size);
	return size;
}
