ifneq ($(KERNELRELEASE),)

obj-m += xt_IPADDR.o
xt_IPADDR-y := xt_IPM.o

else

KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

all:	modules

modules:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean

install:
	cp *.ko /lib/modules/$(shell uname -r)/kernel/net/ipt_ipm/kernel/
	depmod -a
endif
