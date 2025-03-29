
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/malloc.h>
#include <asm/semaphore.h>



#define BUFFERSIZE 1024

static char *buffer;
int buffercount;
int start,end;
int usecount;
struct semaphore sem=MUTEX;
struct wait_queue *read_queue,*write_queue; 

int ring_open(struct inode *inode,struct file *file) 
{
	
	down(&sem);
	usecount++;
	if (usecount == 1) {
	        
	        // kmalloc moze uspic proces - uwaga na synchronizacje
		buffer=kmalloc(BUFFERSIZE,GFP_KERNEL);
		buffercount=start=end=0;
	} 
	up(&sem);
	return 0;
	
}

void ring_release(struct inode *inode,struct file *file) 
{
	usecount--;
	if (usecount==0)
		kfree(buffer);
}

int ring_read(struct inode *inode,struct file *file,char *pB,int count)
{

	int i;
	char tmp;
	for(i=0;i<count;i++) {
		while (buffercount==0) {
			if (usecount==1)
				return i;
	
			interruptible_sleep_on(&read_queue);
			if (current->signal & ~current->blocked) {
				if (i==0)
					return -ERESTARTSYS;
				return i;
			}
		}
		
		tmp=buffer[start];
		start++;
		if (start==BUFFERSIZE)
			start=0;
		buffercount--;
		wake_up(&write_queue);
		put_user(tmp,pB+i);
	}		
	return count;
}

int ring_write(struct inode *inode,struct file *file,const char *pB,int count)
{
	int i;
	char tmp;		
	for(i=0;i<count;i++) {
		tmp=get_user(pB+i);
		while (buffercount==BUFFERSIZE) {
			interruptible_sleep_on(&write_queue);
			if (current->signal & ~current->blocked) {
				if (i==0)
					return -ERESTARTSYS;
				return i;
			}
		}
		buffer[end]=tmp;
		buffercount++;
		end++;
		if (end==BUFFERSIZE)
			end=0;
		wake_up(&read_queue);
	}
	return count;
}


struct file_operations ring_ops = {
	read: ring_read, write:ring_write,
	open:ring_open, release:ring_release};


#define RING_MAJOR 60

void ring_init(void) {
	init_waitqueue(&write_queue);
	init_waitqueue(&read_queue);
	usecount=0;
	register_chrdev(RING_MAJOR,"ring",&ring_ops);
	printk("Ring device initialized\n");
}
