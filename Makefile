.PHONY: all clean

CFLAGS_EXTRA ?= -ggdb3 -O0 -std=c99 -Wall -Werror -Wextra
IN_EXT =mmap_ring_buf.c
#OUT_EXT=
#OUTS := $(addsuffix $(OUT_EXT), $(basename $(wildcard *$(IN_EXT))))
OUTS=mmap_ring_buf

all: tag $(OUTS)
	#sudo ./$(OUTS) /proc/lkmc_mmap
	sshpass -proot123 scp -o StrictHostKeyChecking=no $(OUTS) root@10.1.1.3:~/

tag:
	ctags -R

%$(OUT_EXT): %$(IN_EXT)
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) -o '$@' '$<'

clean:
	rm -f tags
	rm -f '$(OUTS)'
	rm -f *.o                                          

