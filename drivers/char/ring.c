#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/malloc.h>
#include <asm/semaphore.h>



#define DEFAULT_BUFFERSIZE 1024

#define DEVS_COUNT 4

struct RingDev {
	char *buffer;
	int buffersize;
	int buffercount;
	int start;
	int end;
	int usecount;
	struct semaphore sem;
};

static struct RingDev ring_devs[DEVS_COUNT];

struct wait_queue *read_queue,*write_queue; 

static struct RingDev *get_dev(struct inode *inode)
{
	int dev_nr = MINOR(inode->i_rdev);
	return ring_devs + dev_nr;
}

int ring_open(struct inode *inode,struct file *file) 
{
	struct RingDev *dev = get_dev(inode);
	
	down(&dev->sem);
	dev->usecount++;
	if (dev->usecount == 1) {
	        // kmalloc moze uspic proces - uwaga na synchronizacje
		dev->buffer=kmalloc(dev->buffersize,GFP_KERNEL);
		dev->buffercount=dev->start=dev->end=0;
	} 
	up(&dev->sem);
	return 0;
	
}

void ring_release(struct inode *inode,struct file *file) 
{
	struct RingDev *dev = get_dev(inode);

	dev->usecount--;
	if (dev->usecount==0)
		kfree(dev->buffer);
}

int ring_read(struct inode *inode,struct file *file,char *pB,int count)
{
	struct RingDev *dev = get_dev(inode);

	int i;
	char tmp;
	for(i=0;i<count;i++) {
		while (dev->buffercount==0) {
			if (dev->usecount==1)
				return i;
	
			interruptible_sleep_on(&read_queue);
			if (current->signal & ~current->blocked) {
				if (i==0)
					return -ERESTARTSYS;
				return i;
			}
		}
		
		down(&dev->sem);
		tmp=dev->buffer[dev->start];
		dev->start++;
		if (dev->start==dev->buffersize)
			dev->start=0;
		dev->buffercount--;
		up(&dev->sem);

		wake_up(&write_queue);
		put_user(tmp,pB+i);
	}		
	return count;
}

int ring_write(struct inode *inode,struct file *file,const char *pB,int count)
{
	struct RingDev *dev = get_dev(inode);

	int i;
	char tmp;		
	for(i=0;i<count;i++) {
		tmp=get_user(pB+i);
		while (dev->buffercount==dev->buffersize) {
			interruptible_sleep_on(&write_queue);
			if (current->signal & ~current->blocked) {
				if (i==0)
					return -ERESTARTSYS;
				return i;
			}
		}
		down(&dev->sem);
		dev->buffer[dev->end]=tmp;
		dev->buffercount++;
		dev->end++;
		if (dev->end==dev->buffersize)
			dev->end=0;
		up(&dev->sem);
		wake_up(&read_queue);
	}
	return count;
}

#define IOCTL_BUFF_SIZE_WRITE 0x00
#define IOCTL_BUFF_SIZE_READ 0x01

int ring_ioctl(struct inode *inode,struct file *file, unsigned int cmd, unsigned long arg)
{
	struct RingDev *dev = get_dev(inode);
	switch (cmd) {
		case IOCTL_BUFF_SIZE_WRITE: {
			if (dev->buffersize == arg)
				return 0;

			if (arg < 256 || arg > 16 * 1024)
				return -EINVAL;

			down(&dev->sem);
			if (dev->usecount > 0) {
				void *new_buffer = kmalloc(arg, GFP_KERNEL);
				memcpy(new_buffer, dev->buffer, arg < dev->buffersize ? arg : dev->buffersize);
				kfree(dev->buffer);
				dev->buffer = new_buffer;
			}
			dev->buffersize = arg;
			up(&dev->sem);
			return 0;
		};
		case IOCTL_BUFF_SIZE_READ: {
			put_user(dev->buffersize, (int *)(arg));
			return 0;
		}
	}

	return -EINVAL;
}

struct file_operations ring_ops = {
	read: ring_read, write:ring_write,
	open:ring_open, release:ring_release,
	ioctl:ring_ioctl};


#define RING_MAJOR 60

static void ring_devs_init()
{
	int i;
	for (i = 0; i < DEVS_COUNT; ++i) {
		ring_devs[i].buffersize = DEFAULT_BUFFERSIZE;
		ring_devs[i].usecount = 0;
		ring_devs[i].sem = MUTEX;
	}
}

static void ring_init(void)
{
	init_waitqueue(&write_queue);
	init_waitqueue(&read_queue);
	ring_devs_init();
	register_chrdev(RING_MAJOR,"ring",&ring_ops);
	printk("Ring device initialized\n");
}

#ifdef MODULE
int init_module(void)
{
	ring_init();
	return 0;
}

void cleanup_module(void)
{
	int i;
	for (i = 0; i < DEVS_COUNT; ++i)
		if (ring_devs[i].usecount > 0)
			kfree(ring_devs[i].buffer);	
	unregister_chrdev(RING_MAJOR, "ring");
}
#endif
