#ifndef LOADER_H

/*
 * Macros
 */
#define PAGE_ROUND_DOWN(x) (((unsigned long)(x)) & (~(PAGE_SIZE-1)))
#define PAGE_ROUND_UP(x) ((((unsigned long)(x)) + PAGE_SIZE-1) & (~(PAGE_SIZE-1)))

#define CPA_ARRAY 2

#ifdef CONFIG_X86_64
/* Using 64-bit values saves one instruction clearing the high half of low */
#define MY_DECLARE_ARGS(val, low, high)    unsigned long low, high
#define MY_EAX_EDX_VAL(val, low, high) ((low) | (high) << 32)
#define MY_EAX_EDX_RET(val, low, high) "=a" (low), "=d" (high)
#else
#define MY_DECLARE_ARGS(val, low, high)    unsigned long long val
#define MY_EAX_EDX_VAL(val, low, high) (val)
#define MY_EAX_EDX_RET(val, low, high) "=A" (val)
#endif

#define MY_PAGE_KERNEL_NOENC (__pgprot(__PAGE_KERNEL))
#define MY_PAGE_KERNEL_EXEC_NOENC (__pgprot(__PAGE_KERNEL_EXEC))

extern int set_memory_x(unsigned long addr, int numpages);

#define LOADER_H

#endif
