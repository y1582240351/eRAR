#!/bin/bash

# build libbpf
cd ./libbpf/src
DESTDIR=../build make CFLAGS="-fPIC" install
cd ..
sudo cp -rd build/usr/include/bpf /usr/local/include/
sudo mkdir -p /usr/local/libbpf
sudo cp -rd build/usr/lib64/* /usr/local/libbpf/
sudo echo "/usr/local/libbpf" | sudo tee -a /etc/ld.so.conf > /dev/null
sudo ldconfig
cd ..

# build erar-kernel
cd ./erar-kernel
make
cd ..

# build mpich-erar
cd ./mpich-erar
processors=$(nproc)
curr_path=$(pwd)
sh autogen.sh
./configure -prefix="$curr_path"/build --disable-fortran --with-device=ch3:sock
make -j"$processors"
make install -j"$processors"