#include <linux/init.h>   // Macros for module initialization
#include <linux/module.h> // Core header for loading modules
#include <linux/kernel.h> // Kernel logging macros
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/delay.h>

#define _MM_MALLOC_H_INCLUDED
#include <immintrin.h>

__bpf_kfunc int bpf_mm256add(int *arr1, u32 arr1__sz, const int *arr2, u32 arr2__sz);

/* Define a kfunc function */
__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_mm256add(int *arr1, u32 arr1__sz, const int *arr2, u32 arr2__sz)
{
    if (arr1__sz == 0) {
        printk("Size of array cannot be 0\n");
        return -1;
    }
    if (arr2__sz == 0) {
        printk("Size of array not align, arr1: %lu, arr2: %lu\n", arr1__sz, arr2__sz);
        return -1;
    }
    int i;
    for (i = 0; i + 7 < arr1__sz; i += 8) {
        __m256i vec1 = _mm256_loadu_si256((__m256i *)(arr1 + i));
        __m256i vec2 = _mm256_loadu_si256((__m256i *)(arr2 + i));

        __m256i res = _mm256_add_epi32(vec1, vec2);

        _mm256_storeu_si256((__m256i *)(arr1 + i), res);
        _mm256_storeu_si256((__m256i *)(arr2 + i), res);
    }

    for (; i < arr1__sz; i++) {
        arr1[i] = arr1[i] + arr2[i];
        arr2[i] = arr1[i];
    }

    // printk(KERN_INFO "Result array: ");
    // for (int i = 0; i < arr1__sz; i++) {
    //     printk(KERN_CONT "%d ", arr1[i]);
    // }
    // printk(KERN_CONT "\n");
    return 0;
}

__bpf_kfunc_end_defs();

BTF_SET8_START(bpf_kfunc_example_ids_set) // 6.11 use BTF_KFUNC_START and _END
BTF_ID_FLAGS(func, bpf_mm256add)
BTF_SET8_END(bpf_kfunc_example_ids_set)

// Register the kfunc ID set
static const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

// Function executed when the module is loaded
static int __init eSIMD_init(void)
{
    int ret;

    printk(KERN_INFO "Attach eSIMD\n");
    // Register the BTF kfunc ID set
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_kfunc_example_set);
    if (ret)
    {
        pr_err("bpf_kfunc_simd: Failed to register BTF kfunc ID set\n");
        return ret;
    }
    printk(KERN_INFO "bpf_kfunc_simd: Module loaded successfully\n");
    return 0; // Return 0 if successful
}

// Function executed when the module is removed
static void __exit eSIMD_exit(void)
{
    // Unregister the BTF kfunc ID set
    // unregister_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &bpf_kfunc_example_set);
    printk(KERN_INFO "Exit eSIMD\n");
}

// Macros to define the module’s init and exit points
module_init(eSIMD_init);
module_exit(eSIMD_exit);

MODULE_LICENSE("GPL");                 // License type (GPL)
MODULE_AUTHOR("Your Name");            // Module author
MODULE_DESCRIPTION("ebpf simd kfunc"); // Module description
MODULE_VERSION("1.0");                 // Module version