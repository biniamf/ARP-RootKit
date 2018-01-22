# No releases yet

This software is under development.  
There's not even 1 release yet.  
  
# Hooking technique

The idea is to replace the addresses of the sys_call_table in the whole kernel, avoiding anti malware to find hook handlers on the sys_call_table.
It must find the rootkit's sys_call_table from the opcodes in the kernel.

# The first commit of this project

At the beggining, I started doing research of ways of implementing a rootkit without hooking syscalls.
And I found a way of hidding PIDs. The problem is that the process can't terminate ever.
But maybe hooking sys_exit and restoring the pid into the structures of the kernel, it would be possible.

Below an example of the working `rootkit.c` first commit:

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
