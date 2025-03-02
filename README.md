# eRAR 
This is an implementation of accelerating gradient aggregation over Ring-AR by using eBPF.

## Contents
This repository mainly contains two parts:
1. Implementation of eBPF code in eRAR is in `erar-kernel`. We use `ear` to attach the eBPF code to kernel.
2. `mpich-erar` is a modified version of MPICH where we have integrated eRAR.

## Building and Running
Run `build.sh` to complie the code in `erar-kernel` and `mpich-erar`.

> To use the eBPF SIMD function, please run and attach eBPF-SIMD in `eBPF-SIMD/`. Then run `build.sh 1` to complie the code.

### Attach eRAR to Kerenl
We need to modify `erar.conf` to configure the cluster settings. The `erar.conf` follows the following format:
```
# rank id, ip addr, mac addr, num of nic, name of nic
0, 33.33.33.120, b4:05:5d:ac:85:f3, 1, ens27f3
```

Then we can use `./erar-kernel/erar -r <rank-id>` to attach eRAR to kernel.

### Run eRAR with mpi
We have integrated eRAR into MPICH, and by setting environment variables, we can run eRAR directly following the manner of MPI.
```
mpirun -env MPI_EBPF_ALLREDUCE 1 --hostfile <hostfile> -np <num-of-nodes> <execute-file>
```