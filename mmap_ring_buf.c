#define _XOPEN_SOURCE 700
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> /* uintmax_t */
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <unistd.h> /* sysconf */

#include "common.h"
#include "ring_buf.h"

// https://github.com/cirosantilli/linux-kernel-module-cheat/tree/master/kernel_module
// http://egloos.zum.com/furmuwon/v/11206485
// http://wenx05124561.blog.163.com/blog/static/1240008052013101715644618/
// http://chocokeki.tistory.com/672

int main(int argc, char **argv)
{
	int fd;
	long page_size;
	char *addr;
	log_read_info_t rinfo;
	uintptr_t paddr;
	int len, i;
	log_ring_t *logring;
	char *proc_name = "/proc/nslog";

	if (argc >= 2) {
		//printf("Usage: %s <mmap_file>\n", argv[0]);
		//return EXIT_FAILURE;
		proc_name = argv[1];
	}

	//page_size = sysconf(_SC_PAGE_SIZE) * MAX_LOG_MEM_ORDER;
	page_size = sysconf(_SC_PAGE_SIZE);

	printf("open pathname = %s\n, page_size=%lu \n", proc_name, page_size);
	fflush(NULL);

	fd = open(proc_name, O_RDWR | O_SYNC);                                                                      
	if (fd < 0) {
		perror("open");
		assert(0);
	}

	printf("fd = %d\n", fd);

	puts("mmap 1");
	addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		assert(0);
	}

	virt_to_phys_user(&paddr, getpid(), (uintptr_t)addr);
	printf("addr=%p, paddr1 = 0x%jx\n", addr, (uintmax_t)paddr);

	logring = (log_ring_t*)addr;

	printf("magic: 0x%x \n", logring->magic);
	printf("ver: 0x%x \n", logring->ver);
	printf("cnt: %d \n", logring->cnt);
	printf("slot_size: %d, %lu \n", logring->slot_size, sizeof(log_t));
	fflush(NULL);

	//memset(logring->data, 0, logring->cnt * logring->slot_size);

	memset(&rinfo, 0, sizeof(log_read_info_t));
	len = read(fd, (void*)&rinfo, sizeof(log_read_info_t));
	printf("read len=%d \n", len);
	printf("start=%d, cnt=%d \n", rinfo.start, rinfo.cnt);

	for (i=0; i<rinfo.cnt; i++) {
		log_t *log, *base;
		int idx = (rinfo.start + i) % logring->cnt;
		int size = logring->slot_size;

		base = (log_t*)logring->data;
		log = &base[idx];
		printf("log date[%d]=%d:%s \n", idx, log->date, log->msg);
	}

	///// move tail
	logring->tail = (logring->tail + rinfo.cnt) % logring->cnt;

	puts("munmap 1");
	if (munmap(addr, page_size)) {
		perror("munmap");
		assert(0);
	}

	puts("close");
	close(fd);

	return EXIT_SUCCESS;
} 
 

