obj-m += eSIMD.o  

KBUILD_CFLAGS += -g -O2
GCC_VERSION ?= 13
CC_SIMD_OPTS ?= -mavx2

ccflags-y += -I/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VERSION)/include $(CC_SIMD_OPTS)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean