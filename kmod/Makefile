obj-m   := ring_buf_drv.o
KDIR    := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd) 
KDIR="~/linux-4.10.17"
  
all: 
	ctags -R
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

	#sudo rmmod ring_buf_drv
	#sudo insmod ./ring_buf_drv.ko
	sshpass -proot123 scp -o StrictHostKeyChecking=no ring_buf_drv.ko root@10.1.1.3:~/

clean:
	rm -f *.o
	rm -f ring_buf_drv.mod.c Module.symvers  ring_buf_drv.ko  ring_buf_drv.mod.o  tags  modules.order 
