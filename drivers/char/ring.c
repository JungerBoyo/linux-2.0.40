
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/malloc.h>
#include <asm/semaphore.h>



#define BUFFERSIZE 1024

#define DEVS_COUNT 4

struct RingDev {
	char *buffer;
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
		dev->buffer=kmalloc(BUFFERSIZE,GFP_KERNEL);
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
		
		tmp=dev->buffer[dev->start];
		dev->start++;
		if (dev->start==BUFFERSIZE)
			dev->start=0;
		dev->buffercount--;
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
		while (dev->buffercount==BUFFERSIZE) {
			interruptible_sleep_on(&write_queue);
			if (current->signal & ~current->blocked) {
				if (i==0)
					return -ERESTARTSYS;
				return i;
			}
		}
		dev->buffer[dev->end]=tmp;
		dev->buffercount++;
		dev->end++;
		if (dev->end==BUFFERSIZE)
			dev->end=0;
		wake_up(&read_queue);
	}
	return count;
}


struct file_operations ring_ops = {
	read: ring_read, write:ring_write,
	open:ring_open, release:ring_release};


#define RING_MAJOR 60

static void ring_devs_init()
{
	int i;
	for (i = 0; i < DEVS_COUNT; ++i) {
		ring_devs[i].usecount = 0;
		ring_devs[i].sem = MUTEX;
	}
}

void ring_init(void)
{
	init_waitqueue(&write_queue);
	init_waitqueue(&read_queue);
	ring_devs_init();
	register_chrdev(RING_MAJOR,"ring",&ring_ops);
	printk("Ring device initialized\n");
}
