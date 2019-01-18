ifneq ($(KERNELRELEASE),)

obj-m += xt_IPADDR.o
xt_IPADDR-y := xt_IPM.o
KVER    := $(KERNELRELEASE)

else

KVER    = $(shell echo $$kernelver)
KVER    := $(if $(KVER),$(KVER),$(shell uname -r))
endif
KDIR	:= /lib/modules/$(KVER)/build
PWD	:= $(shell pwd)
MKDIR_P = mkdir -p
OUT_DIR := /lib/modules/$(KVER)/kernel/extra/

all:	modules

directories: ${OUT_DIR}

${OUT_DIR}:
	${MKDIR_P} ${OUT_DIR}

modules:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean

directories: ${OUT_DIR}

${OUT_DIR}:
	${MKDIR_P} ${OUT_DIR}

install: directories
	cp *.ko ${OUT_DIR}
	depmod -a
