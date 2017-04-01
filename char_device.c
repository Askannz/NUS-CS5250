#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/ioctl.h>
#define MAJOR_NUMBER 61

#define SCULL_IOC_MAGIC 'k'

#define SCULL_HELLO_NR 1
#define SCULL_WRITE_NR 2
#define SCULL_READ_NR 3
#define SCULL_MAX_NR 3

#define SCULL_DEV_MSG_SIZE 16

#define SCULL_HELLO _IO(SCULL_IOC_MAGIC, SCULL_HELLO_NR)
#define SCULL_WRITE _IOW(SCULL_IOC_MAGIC, SCULL_WRITE_NR, char*)
#define SCULL_READ _IOR(SCULL_IOC_MAGIC, SCULL_READ_NR, char*)

#define SCULL_SIZE 4000000

/* forward declaration */
int scull_open(struct inode *inode, struct file *filep);
int scull_release(struct inode *inode, struct file *filep);
ssize_t scull_read(struct file *filep, char *buf, size_t count, loff_t *f_pos);
ssize_t scull_write(struct file *filep, const char *buf, size_t count, loff_t *f_pos);
static void scull_exit(void);
static loff_t scull_llseek(struct file *filep, loff_t offset, int whence);
long scull_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);

/* definition of file_operation structure */
struct file_operations scull_fops = {
    read: scull_read,
    write: scull_write,
    open: scull_open,
    release: scull_release,
	llseek: scull_llseek,
	unlocked_ioctl: scull_ioctl
};

char *data = NULL;
size_t data_size = 0;

char *dev_msg;

int scull_open(struct inode *inode, struct file *filep)
{
	filep->private_data = kmalloc(sizeof(loff_t), GFP_KERNEL);
	if(filep->private_data == NULL)
	{
		printk(KERN_ALERT "Failed to allocate private data");
		return -EFAULT;
	}
	
	loff_t *pPos = (loff_t*) filep->private_data;
	*pPos = 0;
	
	if((filep->f_flags & O_ACCMODE) == O_WRONLY || (filep->f_flags & O_ACCMODE) == O_RDWR)
	{
		printk(KERN_ALERT "Opened in write mode\n");
		data_size = 0;
	}
	else
	{		
		printk(KERN_ALERT "Opened in read mode\n");
	}

    return 0; // always successful
}

int scull_release(struct inode *inode, struct file *filep)
{
	kfree(filep->private_data);
    return 0; // always successful
}

ssize_t scull_read(struct file *filep, char *buf, size_t count, loff_t *f_pos)
{
    size_t size_copy = 0;
	loff_t *pPos = (loff_t*) filep->private_data;
	
    if(*pPos == data_size || count == 0)
        return 0;

    if(count + *pPos <= data_size)
		size_copy = count;
    else
		size_copy = data_size - *pPos;
    
    int errors_count = copy_to_user(buf, &data[*pPos], size_copy);
    
    if(errors_count != 0)
    {
        printk(KERN_ALERT "4MB device : failed to read.\n");
        return -EFAULT;
    }
    else
    {
        *pPos += size_copy;
        return size_copy;
    }
}

ssize_t scull_write(struct file *filep, const char *buf, size_t count, loff_t *f_pos)
{
    int not_enough_space = 0;
    size_t size_copy = 0;    
	loff_t *pPos = (loff_t*) filep->private_data;

    if(count == 0)
        return 0;
	
	if(count + *pPos <= SCULL_SIZE)
	   size_copy = count;
	else
	{
	    size_copy = SCULL_SIZE - *pPos;
	    not_enough_space = 1;
	}

	memcpy(&data[*pPos], buf, size_copy);

	*pPos += size_copy;

	if(*pPos > data_size)
		data_size = *pPos;

    if(not_enough_space)
        return -ENOSPC;
    else
        return size_copy;
}

static int scull_init(void)
{
    int result;
    
    // register the device
    result = register_chrdev(MAJOR_NUMBER, "scull", &scull_fops);
    if (result < 0) {
        return result;
    }
    
    // allocate memory for storage
    // kmalloc is just like malloc, the second parameter is
    // the type of memory to be allocated.
    // To release the memory allocated by kmalloc, use kfree.
    data = kmalloc(sizeof(char) * SCULL_SIZE, GFP_KERNEL);
    dev_msg = kmalloc(sizeof(char) * SCULL_DEV_MSG_SIZE, GFP_KERNEL);
    if (!data || !dev_msg) {
        scull_exit();
        // cannot allocate memory
        // return no memory error, negative signify a failure
        return -ENOMEM;
    }
    
    data_size = 0;
    printk(KERN_ALERT "This is a 4MB device module\n");
    return 0;
}

static void scull_exit(void)
{
    // if the pointer is pointing to something
    if (data) {
        // free the memory and assign the pointer to NULL
        kfree(data);
        data = NULL;
    }
    
	if (dev_msg) {
        kfree(dev_msg);
        dev_msg = NULL;
    }
    
    // unregister the device
    unregister_chrdev(MAJOR_NUMBER, "scull");
    printk(KERN_ALERT "4MB device module is unloaded\n");
}

static loff_t scull_llseek(struct file *filep, loff_t offset, int whence)
{
	printk(KERN_ALERT "LSEEK");
	loff_t *pPos = (loff_t*) filep->private_data;
	
	loff_t newPos = 0;

	if(whence == SEEK_CUR)
		newPos = *pPos + offset;
	else if(whence == SEEK_SET)
		newPos = offset;
	else if(whence == SEEK_END)
		newPos = data_size + offset;
	else
		return -EINVAL; // Invalid whence argument

	if(newPos < 0)
		return -EINVAL; // Invalid offset argument
	else if(newPos >= data_size) // If offset goes beyond the end of the file
	{
		if(newPos > SCULL_SIZE)
			return -EINVAL;
		else
		{	
			// Expand the file and pad with zeroes (this is the expected behavior for lseek)
			memset(&data[data_size], 0, newPos - data_size);
			data_size = newPos;
		}
	}	
	
	*pPos = newPos;

	return *pPos;
}

long scull_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	int err = 0, retval = 0;
	char *user_buffer = NULL;

	if(_IOC_TYPE(cmd) != SCULL_IOC_MAGIC ||
		_IOC_NR(cmd) > SCULL_MAX_NR)
		return -ENOTTY;

	if(_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok(VERIFY_WRITE, (void __user*)arg, _IOC_SIZE(cmd));
	else if(_IOC_DIR(cmd) & _IOC_WRITE)
		err = !access_ok(VERIFY_READ, (void __user*)arg, _IOC_SIZE(cmd));

	if(err)
		return -EFAULT;

	switch(cmd)
	{
		case SCULL_HELLO :
			printk(KERN_WARNING "Hello\n");
			break;

		case SCULL_WRITE :
			user_buffer = (char*)arg;
			memcpy(dev_msg, user_buffer, SCULL_DEV_MSG_SIZE);
			break;

		case SCULL_READ :
			user_buffer = (char*)arg;
			int errors_count = copy_to_user(user_buffer, dev_msg, SCULL_DEV_MSG_SIZE);	
			if(errors_count != 0)
			{
				printk(KERN_ALERT "4MB device : failed to read dev_msg.\n");
				return -EFAULT;
			}
			break;

		default:
			return -ENOTTY;
	}

	return retval;
}

MODULE_LICENSE("GPL");
module_init(scull_init);
module_exit(scull_exit);
