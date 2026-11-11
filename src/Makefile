obj-m += xt_tls.o
xt_tls-objs := xt_tls_main.o hostset_tls.o utils_tls.o

KERNELRELEASE ?= $(shell uname -r)
KERNELDIR ?= /lib/modules/$(KERNELRELEASE)/build
PREFIX ?= /usr
DESTDIR ?=
SRCDIR ?= $(PREFIX)/src
DKMSDIR ?= $(SRCDIR)/xt_tls
DEPMOD ?= depmod
DEPMODBASEDIR ?= $(if $(DESTDIR),$(DESTDIR),/)

PWD := $(shell pwd)

# Build workarounds for some 7.0.x kernels. Override with `make KBUILD_EXTRA=`
# to build normally on other kernels.
#   KCFLAGS=-g0                          -> avoid ld .debug_info bad-reloc link failure
#   CONFIG_DEBUG_INFO_BTF_MODULES= (empty) -> skip BTF generation (no pahole needed)
KBUILD_EXTRA ?= KCFLAGS="-g0" CONFIG_DEBUG_INFO_BTF_MODULES=

all: prepare
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $(KBUILD_EXTRA) modules
	rm -rf hostset_tls.c utils_tls.c


debug: module-debug

prepare:
	cp  hostset.c hostset_tls.c
	cp  utils.c utils_tls.c

module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $(KBUILD_EXTRA) modules

module-debug: prepare
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $(KBUILD_EXTRA) CFLAGS_MODULE="-DXT_TLS_DEBUG -DDEBUG" modules
	rm -rf hostset_tls.c utils_tls.c


clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -rf hostset_tls.c utils_tls.c


module-install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) INSTALL_MOD_PATH=$(DESTDIR) modules_install
	$(DEPMOD) -b "$(DEPMODBASEDIR)" -a $(KERNELRELEASE)

install: module-install

reload: all
	(lsmod | grep -w xt_[t]ls && sudo rmmod xt_tls) || true
	sudo insmod xt_tls.ko
