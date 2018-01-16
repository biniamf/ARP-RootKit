cmd_/home/diwou/arprootkit/capstone/SStream.o := gcc -Wp,-MD,/home/diwou/arprootkit/capstone/.SStream.o.d  -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/5/include  -I./arch/x86/include -I./arch/x86/include/generated  -I./include -I./arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/kconfig.h -Iubuntu/include  -D__KERNEL__ -fno-pie -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -Werror-implicit-function-declaration -Wno-format-security -std=gnu89 -fno-PIE -fno-pie -no-pie -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -falign-jumps=1 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -mtune=generic -mno-red-zone -mcmodel=kernel -funit-at-a-time -DCONFIG_X86_X32_ABI -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -DCONFIG_AS_CFI_SECTIONS=1 -DCONFIG_AS_FXSAVEQ=1 -DCONFIG_AS_SSSE3=1 -DCONFIG_AS_CRC32=1 -DCONFIG_AS_AVX=1 -DCONFIG_AS_AVX2=1 -DCONFIG_AS_AVX512=1 -DCONFIG_AS_SHA1_NI=1 -DCONFIG_AS_SHA256_NI=1 -pipe -Wno-sign-compare -fno-asynchronous-unwind-tables -fno-delete-null-pointer-checks -O2 --param=allow-store-data-races=0 -DCC_HAVE_ASM_GOTO -Wframe-larger-than=1024 -fstack-protector-strong -Wno-unused-but-set-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-var-tracking-assignments -pg -mfentry -DCC_USING_FENTRY -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow -fconserve-stack -Werror=implicit-int -Werror=strict-prototypes -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -O0 -I/home/diwou/arprootkit/capstone/include -DCAPSTONE_USE_SYS_DYN_MEM -DCAPSTONE_HAS_X86  -DMODULE  -DKBUILD_BASENAME='"SStream"'  -DKBUILD_MODNAME='"arprk"' -c -o /home/diwou/arprootkit/capstone/SStream.o /home/diwou/arprootkit/capstone/SStream.c

source_/home/diwou/arprootkit/capstone/SStream.o := /home/diwou/arprootkit/capstone/SStream.c

deps_/home/diwou/arprootkit/capstone/SStream.o := \
  /usr/lib/gcc/x86_64-linux-gnu/5/include/stdarg.h \
  /home/diwou/arprootkit/capstone/include/platform.h \
  include/linux/types.h \
    $(wildcard include/config/have/uid16.h) \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/lbdaf.h) \
    $(wildcard include/config/arch/dma/addr/t/64bit.h) \
    $(wildcard include/config/phys/addr/t/64bit.h) \
    $(wildcard include/config/64bit.h) \
  include/uapi/linux/types.h \
  arch/x86/include/uapi/asm/types.h \
  include/uapi/asm-generic/types.h \
  include/asm-generic/int-ll64.h \
  include/uapi/asm-generic/int-ll64.h \
  arch/x86/include/uapi/asm/bitsperlong.h \
  include/asm-generic/bitsperlong.h \
  include/uapi/asm-generic/bitsperlong.h \
  include/uapi/linux/posix_types.h \
  include/linux/stddef.h \
  include/uapi/linux/stddef.h \
  include/linux/compiler.h \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/kasan.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/enable/warn/deprecated.h) \
  include/linux/compiler-gcc.h \
    $(wildcard include/config/arch/supports/optimized/inlining.h) \
    $(wildcard include/config/optimize/inlining.h) \
    $(wildcard include/config/gcov/kernel.h) \
    $(wildcard include/config/stack/validation.h) \
    $(wildcard include/config/arch/use/builtin/bswap.h) \
  arch/x86/include/asm/posix_types.h \
    $(wildcard include/config/x86/32.h) \
  arch/x86/include/uapi/asm/posix_types_64.h \
  include/uapi/asm-generic/posix_types.h \
  /home/diwou/arprootkit/capstone/include/inttypes.h \
  include/linux/string.h \
    $(wildcard include/config/binary/printf.h) \
    $(wildcard include/config/fortify/source.h) \
  include/uapi/linux/string.h \
  arch/x86/include/asm/string.h \
  arch/x86/include/asm/string_64.h \
    $(wildcard include/config/kmemcheck.h) \
    $(wildcard include/config/x86/mce.h) \
    $(wildcard include/config/arch/has/uaccess/flushcache.h) \
  include/linux/jump_label.h \
    $(wildcard include/config/jump/label.h) \
  arch/x86/include/asm/jump_label.h \
    $(wildcard include/config/x86/64.h) \
  arch/x86/include/asm/asm.h \
  arch/x86/include/asm/nops.h \
    $(wildcard include/config/mk7.h) \
    $(wildcard include/config/x86/p6/nop.h) \
  include/linux/stringify.h \
  /home/diwou/arprootkit/capstone/SStream.h \
  /home/diwou/arprootkit/capstone/cs_priv.h \
  /home/diwou/arprootkit/capstone/include/capstone.h \
  /home/diwou/arprootkit/capstone/include/platform.h \
  /home/diwou/arprootkit/capstone/include/arm.h \
  /home/diwou/arprootkit/capstone/include/arm64.h \
  /home/diwou/arprootkit/capstone/include/mips.h \
  /home/diwou/arprootkit/capstone/include/ppc.h \
  /home/diwou/arprootkit/capstone/include/sparc.h \
  /home/diwou/arprootkit/capstone/include/systemz.h \
  /home/diwou/arprootkit/capstone/include/x86.h \
  /home/diwou/arprootkit/capstone/include/xcore.h \
  /home/diwou/arprootkit/capstone/MCInst.h \
  /home/diwou/arprootkit/capstone/include/capstone.h \
  /home/diwou/arprootkit/capstone/utils.h \
  /usr/lib/gcc/x86_64-linux-gnu/5/include/stddef.h \

/home/diwou/arprootkit/capstone/SStream.o: $(deps_/home/diwou/arprootkit/capstone/SStream.o)

$(deps_/home/diwou/arprootkit/capstone/SStream.o):
