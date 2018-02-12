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
