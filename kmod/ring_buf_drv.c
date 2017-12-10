#include <asm/uaccess.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/jiffies.h>

#include "../ring_buf.h"

static void mykmod_timer_handler(unsigned long data);
static unsigned long onesec;

DEFINE_TIMER(mytimer, mykmod_timer_handler, 0, 0);


static const char *log_ring_name = "nslog";

typedef struct hslog_info_s {
	wait_queue_head_t wq;
	log_ring_t 		*logring;
	uint32_t 		logring_size;
} nslog_info_t;

nslog_info_t g_nslog;


void log_ring_free_buffer(unsigned long virtaddr, uint32_t buf_size);

///////////////////////////////////
//

void log_ring_vm_close(struct vm_area_struct *vma)
{
	printk("log_ring_vm_close\n");
}

#if 0
int log_ring_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page;
	nslog_info_t *loginfo;
	log_ring_t *logring;
	unsigned long offset;

	offset = vmf->pgoff << PAGE_SHIFT;

	printk("log_ring_vm_fault:offset=%lu\n", offset);

	loginfo = (nslog_info_t*)vma->vm_private_data;
	logring = loginfo->logring;

	if (logring) {
		page = virt_to_page(logring);
		get_page(page);
		vmf->page = page;
	}

	return 0;
}
#endif

void log_ring_vm_open(struct vm_area_struct *vma)
{
	printk("log_ring_vm_open\n");
}

static struct vm_operations_struct log_ring_vm_ops =
{
	.open  = log_ring_vm_open,
	.close = log_ring_vm_close,
	//.fault = log_ring_vm_fault,
};

int log_ring_mmap(struct file *filp, struct vm_area_struct *vma)
{
	nslog_info_t *loginfo;
	log_ring_t *logring;

	unsigned long start = vma->vm_start;
	unsigned long size = (vma->vm_end - vma->vm_start);
	void *pos;

	printk("log_ring_mmap\n");

	vma->vm_ops = &log_ring_vm_ops;
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_private_data = filp->private_data;

	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	loginfo = (nslog_info_t*)vma->vm_private_data;
	logring = loginfo->logring;
	pos = logring;

	vma->vm_pgoff = virt_to_phys((void *)logring) >> PAGE_SHIFT;

	while (size > 0) {
		unsigned long pfn;

		pfn = virt_to_phys((void *) pos) >> PAGE_SHIFT;
		if (remap_pfn_range(vma, start, pfn, PAGE_SIZE, PAGE_SHARED))
			return -EAGAIN;

		start += PAGE_SIZE;
		pos += PAGE_SIZE;
		size -= PAGE_SIZE;
	}

	log_ring_vm_open(vma);

	return 0;
}

int log_ring_open(struct inode *inode, struct file *filp)
{
	filp->private_data = &g_nslog;

	return 0;
}

ssize_t log_ring_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
    int ret=0;
	log_ring_t *logring;
	nslog_info_t *nslog;
	log_read_info_t rinfo;

	printk("log_ring_read: dest buf len=%lu\n", len);
	nslog = (nslog_info_t*)filp->private_data;
	logring = nslog->logring;

	ret = sizeof(log_read_info_t);

	if (len < ret) {
		return -EINVAL;
	}

	//wait_event_interruptible(nslog->wq, logring->head != logring->tail);

	rinfo.start = logring->tail;

	if (logring->head > logring->tail) {
		rinfo.cnt = logring->head - logring->tail;
	}
	else {
		rinfo.cnt = (logring->cnt - logring->tail) + logring->head;
	}

	printk("idx=%d:%d, start=%d, cnt=%d", logring->head, logring->tail, rinfo.start, rinfo.cnt);

    if (copy_to_user(buf, &rinfo, ret)) {
        ret = -EFAULT;
	}

	return ret;
}

int log_ring_push_log(uint64_t jiff)
{
	log_ring_t *logring;
	log_t *log, *base;
	uint32_t next_idx;

	logring = g_nslog.logring;
	base = (log_t*)logring->data;
	log = &base[logring->head];

	///////////////////
	// copy log
	log->date = jiff;
	sprintf(log->msg, "msg: %llu", jiff);
	printk("push log[%d]: %s \n", logring->head, log->msg);
	///////////////////
	
	next_idx = (logring->head + 1) % logring->cnt;
	logring->head = next_idx;
	if (logring->tail == next_idx) {
		printk("ring is full: tail(%d) orver writed", logring->tail);
		logring->tail = (next_idx + 1) % logring->cnt;
	}

	logring->head = next_idx;

	if (waitqueue_active(&g_nslog.wq)) {
		wake_up_interruptible(&g_nslog.wq);
	}

	return 0;
}


ssize_t log_ring_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
#if 0
	struct mmap_info *info;
	offset = (vmf->address - vma->vm_start) >> PAGE_SHIFT;
	offset = (vmf->address - vma->vm_start) >> PAGE_SHIFT;
	page = bo->pages[offset];

	err = vm_insert_page(vma, vmf->address, page);
	switch (err) {
	case -EAGAIN:
	page = bo->pages[offset];

	err = vm_insert_page(vma, vmf->address, page);
	switch (err) {
	case -EAGAIN:

	printk("log_ring_write\n");
	info = filp->private_data;
    if (copy_from_user(info->data, buf, min(len, (size_t)BUFFER_SIZE))) {
        return -EFAULT;
	} 
	else {
		return len;
	}
#else
	return len;
#endif
}

int log_ring_release(struct inode *inode, struct file *filp)
{
	printk("log_ring_release\n");
	filp->private_data = NULL;
	
	return 0;
}

/////////////////////////////////////////////////////
//

static void mykmod_timer_handler(unsigned long data)
{
	//pr_info("mykmod timer %u jiffies\n", (unsigned)jiffies);

	log_ring_push_log(jiffies);
	mod_timer(&mytimer, jiffies + onesec);
}

static const struct file_operations log_ring_fops = {
	.mmap = log_ring_mmap,
	.open = log_ring_open,
	.read = log_ring_read,
	.release = log_ring_release,
	//.write = log_ring_write,
};

void log_ring_free_buffer(unsigned long virtaddr, uint32_t buf_size)
{
	uint32_t order, size;
	unsigned long addr = virtaddr;

	size = PAGE_ALIGN(buf_size);
	order = get_order(size);

	while (size > 0) {
		ClearPageReserved(virt_to_page(addr));
		addr += PAGE_SIZE;
		size -= PAGE_SIZE;
	}

	free_pages((unsigned long) virtaddr, order);
}

uint32_t log_ring_alloc_buffer(char **virt_addr)
{
	uint32_t order, size = 0, allocted_size = 0;
	unsigned long vaddr, addr;
	uint32_t i;

	for (i=MAX_LOG_MEM_ORDER; i >= 0; i --) {
		size = PAGE_SIZE * (1 << i);
		size = PAGE_ALIGN(size);
		order = get_order(size);

		allocted_size = size;

		vaddr = __get_free_pages(GFP_KERNEL|GFP_NOWAIT, order);
		addr = vaddr;

		if (vaddr == 0) {
			size = 0;
			printk("Cannot alloc log mem: continuous mem=%u \n", size);
			continue;
		}

		memset((char*)vaddr, 0, size);

		while (size > 0) {
			SetPageReserved(virt_to_page(addr));
			addr += PAGE_SIZE;
			size -= PAGE_SIZE;
		}

		//*phys_addr = (char*)virt_to_phys((void *)vaddr);
		*virt_addr = (char*)vaddr;

		break;
	}

	return allocted_size;
}

int log_ring_init(void)
{
	log_ring_t *logring = NULL;
	uint32_t len = 0;
	int i, cnt;
	char *u = NULL;

	memset(&g_nslog, 0, sizeof(nslog_info_t));
	init_waitqueue_head(&g_nslog.wq);

	printk("================ log_ring_init\n");

	len = log_ring_alloc_buffer(&u);
	logring = (log_ring_t*)u;

	if (logring == NULL || len == 0) {
		printk("Fail to alloc pages \n");
		return -ENOMEM;
	}

	logring->magic = 0x26;
	logring->ver   = 0x34;
	logring->head  = 0;
	logring->tail  = 0;
	logring->slot_size = sizeof(log_t);

	g_nslog.logring_size = len;
	printk("Log ring total size: %u \n", len);

	len = len - (uint32_t)sizeof(log_ring_t);
	cnt = len / (uint32_t)sizeof(log_t);
	logring->cnt = cnt;

	printk("Log ring size: %u \n", len);
	printk("Slot Count: %u(%lu) \n", cnt, sizeof(log_t));

	// init all slots
	for (i=0; i<logring->cnt; i++) {
		log_t *base;

		base = (log_t*)logring->data;
		base[i].date = i + 100;
	}

	g_nslog.logring = logring;

	proc_create(log_ring_name, 0, NULL, &log_ring_fops);

	onesec = msecs_to_jiffies(1000 * 3);

	// mykmod_timer_handler()
	mod_timer(&mytimer, jiffies + onesec);

	return 0;
}

void log_ring_exit(void)
{
	del_timer(&mytimer);

	if (waitqueue_active(&g_nslog.wq)) {
		wake_up_interruptible(&g_nslog.wq);
	}

	remove_proc_entry(log_ring_name, NULL);

	printk("log_ring_exit\n");

	if (g_nslog.logring) {
		log_ring_free_buffer((unsigned long)g_nslog.logring, g_nslog.logring_size);
	}

}

module_init(log_ring_init)
module_exit(log_ring_exit)
MODULE_LICENSE("GPL");

