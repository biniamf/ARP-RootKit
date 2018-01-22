obj-m += arprk.o
arprk-objs := loader.o kernel-asm.o capstone/cs.o capstone/utils.o capstone/SStream.o capstone/MCInstrDesc.o capstone/MCRegisterInfo.o capstone/arch/X86/X86DisassemblerDecoder.o capstone/arch/X86/X86Disassembler.o capstone/arch/X86/X86IntelInstPrinter.o capstone/arch/X86/X86ATTInstPrinter.o capstone/arch/X86/X86Mapping.o capstone/arch/X86/X86Module.o capstone/MCInst.o

EXTRA_CFLAGS := -O0 -I$(PWD)/capstone/include -DCAPSTONE_USE_SYS_DYN_MEM -DCAPSTONE_HAS_X86

KERNEL_HEADERS = /lib/modules/$(shell uname -r)/build

CFLAGS_kernel.o := -mcmodel=small -fpic -fpie -fPIE -pie

all: arprk

reloctest:
	echo "\t.text" > reloc_test-asm.s
	gcc -mcmodel=small -fno-pie -no-pie -fno-PIE -fpic -fpie -pie -fPIE -S reloc_test.c
	grep -vE "\.cfi|\.file|\.text|\.rodata|\.bss|\.data|\.version|\.section|\.align|\.p2align|\.balign|\.ident|__fentry__|__stack_chk_fail" reloc_test.s >> reloc_test-asm.s 
	#| sed -e 's/movl\t\$$\.LC\([0-9]\+\), %e\([a-z]\{2\}\)/movabs\t\$$\.LC\1, %r\2/g' >> reloc_test-asm.s
	gcc -o reloc_test reloc_test-asm.s

arprk:
	make V=1 -C $(KERNEL_HEADERS) M=$(PWD) kernel.s
	echo "\t.data" > kernel-asm.s
	grep -vE "\.file|\.text|\.rodata|\.bss|\.data|\.version|\.section|\.align|\.p2align|\.balign|\.ident|__fentry__|__stack_chk_fail" kernel.s | sed -e 's/current_task@PLT/current_task/g' >> kernel-asm.s
	#python relocate-arrays.py > kernel-asm.relocated.s
	#mv kernel-asm.relocated.s kernel-asm.s
	gcc -o kernel-asm.o -c kernel-asm.s
	make V=1 -C $(KERNEL_HEADERS) M=$(PWD) modules

clean:
	make V=1 -C $(KERNEL_HEADERS) M=$(PWD) clean
	rm -f *.plist
