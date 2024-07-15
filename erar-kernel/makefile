LIBBPF_PATH := ../libbpf/build/usr
INCLUDE_PATH := -I/usr/include -I/usr/include/x86_64-linux-gnu -I$(LIBBPF_PATH)/include
bpftool := $(shell which bpftool)
LIBBPF_OBJ := $(abspath $(LIBBPF_PATH)/lib64/libbpf.a)
CLANG := clang-15
CFLAGS := -g -O2
SRCDIR := $(abspath .)
target := erar
SRC_TARGET := $(SRCDIR)/$(target)
DEV := lo

DEBUG ?= 


ifdef DEBUG
	CFLAGS += -D DEBUG
endif

.DEBFAULT: build

build:$(LIBBPF_OBJ) $(SRCDIR)/vmlinux.h
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_x86 $(INCLUDE_PATH) -c $(SRC_TARGET).bpf.c -o $(target).bpf.o 
	$(CLANG) $(CFLAGS) -Wall $(INCLUDE_PATH) -c $(SRC_TARGET).c -o $(target).o
	$(CLANG) -Wall $(CFLAGS) $(target).o -static $(LIBBPF_OBJ) -lelf -lz -lzstd -o $(target)


$(SRCDIR)/vmlinux.h:
	$(bpftool) btf dump file /sys/kernel/btf/vmlinux format c > $(SRCDIR)/vmlinux.h

attach:
	sudo tc qdisc add dev $(DEV) clsact
	sudo tc filter add dev $(DEV) ingress bpf da obj mpi-reduce.bpf.o sec ResendGen

detach:
	-sudo rm /sys/fs/bpf/mpi_rank_infos /sys/fs/bpf/submit_rb /sys/fs/bpf/rank_tmp_buff /sys/fs/bpf/data_blocks /sys/fs/bpf/EarlyPacket /sys/fs/bpf/ResendGen /sys/fs/bpf/net_infos
	-sudo tc filter del dev $(DEV) ingress
	-sudo tc filter del dev $(DEV) egress
	-sudo tc qdisc del dev $(DEV) clsact
	-sudo bpftool net detach xdpgeneric dev $(DEV)
	-sudo bpftool net detach xdp dev $(DEV)
	-sudo bpftool net detach xdpdrv dev $(DEV)
	-sudo tc filter del dev $(DEV) ingress
	-sudo tc filter del dev $(DEV) egress
	-sudo tc qdisc del dev $(DEV) clsact
	-sudo bpftool net detach xdpgeneric dev $(DEV)
	-sudo bpftool net detach xdp dev $(DEV)
	-sudo bpftool net detach xdpdrv dev $(DEV)

clean:
	rm -rf $(target).bin *.o ../src/$(target).skel.h 
cleanall:
	rm -rf $(target) *.o ../src/$(target).skel.h libbpf.* staticobjs ../src/libbpf/usr/include ../src/vmlinux.h ../crashtest/*.bin