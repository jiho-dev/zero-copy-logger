  1 #define _XOPEN_SOURCE 700
  2 #include <assert.h>
  3 #include <fcntl.h>
  4 #include <stdio.h>
  5 #include <stdlib.h>
  6 #include <stdint.h> /* uintmax_t */
  7 #include <string.h>
  8 #include <strings.h>
  9 #include <sys/mman.h>
 10 #include <unistd.h> /* sysconf */
 11     
 12 #include "common.h" /* virt_to_phys_user */
 13 #include "ring_buf.h" /* virt_to_phys_user */
 14     
 15 // https://github.com/cirosantilli/linux-kernel-module-cheat/tree/master/kernel_module
 16 // http://egloos.zum.com/furmuwon/v/11206485
 17 // http://wenx05124561.blog.163.com/blog/static/1240008052013101715644618/
 14 
 12 #include "common.h" /* virt_to_phys_user */
 11 
 10 #include <unistd.h> /* sysconf */
 11 
 12 #include "common.h" /* virt_to_phys_user */
 13 #include "ring_buf.h" /* virt_to_phys_user */
 14 
 15 // https://github.com/cirosantilli/linux-kernel-module-cheat/tree/master/kernel_module
 16 // http://egloos.zum.com/furmuwon/v/11206485
 17 // http://wenx05124561.blog.163.com/blog/static/1240008052013101715644618/
 18 // http://chocokeki.tistory.com/672
 19     
 20 int main(int argc, char **argv)
 21 {   
 22     int fd;
 23     long page_size;
 24     char *addr;
 25     log_read_info_t rinfo;
 26     uintptr_t paddr;
 27     int len, i;
 28     log_ring_t *logring;
 29         
 30     if (argc < 2) {
 31         printf("Usage: %s <mmap_file>\n", argv[0]);
 32         return EXIT_FAILURE;
 33     }
 34     
 35     page_size = sysconf(_SC_PAGE_SIZE) * MAX_LOG_MEM_ORDER;
 36     printf("open pathname = %s\n, page_size=%lu \n", argv[1], page_size);
 37     fflush(NULL);
 38 
 39     fd = open(argv[1], O_RDWR | O_SYNC);
 40     if (fd < 0) {
 41         perror("open");
 42         assert(0);
 43     }
 44 
 45     printf("fd = %d\n", fd);
 46 
 47     puts("mmap 1");
 48     addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
 49     if (addr == MAP_FAILED) {
 50         perror("mmap");
 51         assert(0);                                                                                              
 52     }
 53 
 54     virt_to_phys_user(&paddr, getpid(), (uintptr_t)addr);
 55     printf("addr=%p, paddr1 = 0x%jx\n", addr, (uintmax_t)paddr);
 56 
 57     logring = (log_ring_t*)addr;
 58 
 59     printf("magic: 0x%x \n", logring->magic);
 60     printf("ver: 0x%x \n", logring->ver);
 61     printf("cnt: %d \n", logring->cnt);
 62     printf("slot_size: %d, %lu \n", logring->slot_size, sizeof(log_t));
 63     fflush(NULL);
 64 
 65     //memset(logring->data, 0, logring->cnt * logring->slot_size);
