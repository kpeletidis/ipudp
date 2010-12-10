ifneq ($(KERNELRELEASE),)
obj-m		:= ipudp.o
ipudp-objs 	:= ipudp_mod.o ipudp_genl.o

else
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
endif


.PHONY: clean

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c *.markers *.symvers *.order
