## Build and Attach eBPF-SIMD
Build and attach eBPF-SIMD as follows:
```bash
cd eBPF-SIMD
make
sudo insmod eSIMD.ko
```
Print the kernel output:
```bash
sudo dmesg | tail
```
Detach eBPF-SIMD:
```bash
sudo rmmod eSIMD
```