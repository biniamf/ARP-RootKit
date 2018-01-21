# No releases yet

This software is under development.  
There's not even 1 release yet.  
  
Atm I can copy the rootkit kernel into a memory area reserved with kmalloc, and this code is relocatable in any place just by the way it's coded.  
Checking the protections of the kernel memory pages, we can locate the rootkit in a rwx memory area. By that fault, I'm trying to do variants of the releases after developed this way of detection.  

# Planning of releases

- 1st release: hooking system by replacing syscall addresses from sys_call_table (the well-known way).
- 2nd release: hooking system by hooking inside the syscalls (helped by capstone).
- 3rd release: hooking system by replacing the address of the sys_call_table in the int 0x80 and the SYSCALL handler.
- 4th realase: try to hide processes, files and connections in a different way than hooking syscalls.

# An example of working of process hidding of the 4th release (rootkit.c first commit)

```
diwou@diwou-VirtualBox:~/arprootkit$ ps auwx | grep bash | grep root
root      3924  0.0  0.1  61932  4052 pts/9    S    13:10   0:00 sudo bash
root      3925  0.0  0.1  29960  5444 pts/9    S+   13:10   0:00 bash
diwou@diwou-VirtualBox:~/arprootkit$ grep 392 rootkit.c
        hide_pid(3924);
        hide_pid(3925);
diwou@diwou-VirtualBox:~/arprootkit$ sudo insmod rootkit.ko
find_vpid ffff9df24f34c180
Ok
find_vpid ffff9df24f34cb00
Ok
diwou@diwou-VirtualBox:~/arprootkit$ ps auwx | grep bash | grep root
diwou@diwou-VirtualBox:~/arprootkit$ ls /proc/3924
ls: no se puede acceder a '/proc/3924': No existe el archivo o el directorio
diwou@diwou-VirtualBox:~/arprootkit$ ls /proc/3925
ls: no se puede acceder a '/proc/3925': No existe el archivo o el directorio
diwou@diwou-VirtualBox:~/arprootkit$ sudo rmmod rootkit
Ok
Ok
diwou@diwou-VirtualBox:~/arprootkit$ ps auwx | grep bash | grep root
root      3924  0.0  0.1  61932  4052 pts/9    S    13:10   0:00 sudo bash
root      3925  0.0  0.1  29960  5444 pts/9    S+   13:10   0:00 bash
```
