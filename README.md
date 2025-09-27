# decloacker
a simple tool to reveal files, directories and connections hidden by malware.

### Usage

tl;dr: `./bin/decloacker --help`

There're 4 main areas:

 - cat, list, move, delete or copy files without the libc.
   
   Useful for LD_PRELOAD based rootkits.

```bash
  cp [<orig> [<dest>]] [flags]
    Copy file via syscalls.

  rm <paths> ... [flags]
    Delete files via syscalls.

  ls [<paths> ...] [flags]
    List files via syscalls.

  mv [<orig> [<dest>]] [flags]
    Move files via syscalls.

  cat [<paths> ...] [flags]
    Cat files via syscalls.
```

 - list, copy or get info of directories and files by accessing directly the disk device.
   
   These options help to manipulate files or directories hidden by some kernel rootkits (like Diamorphine).

```bash
  disk ls --dev=STRING <paths> ... [flags]
    List directories and files by reading directly from the disk device

  disk cp --dev=STRING <orig> <dest> [flags]
    Copy directories and files directly from the disk device

  disk info --dev=STRING <paths> ... [flags]
    Return information about a path
```

 - execute actions to unhide files, directories, processes or kernel rootkits
   
```bash
  scan hidden-files <paths> ... [flags]
    Look for hidden files, directories or processes (libc vs Go's std lib vs mmap).

  scan hidden-content <paths> ...
    Open a file and check if it has hidden content (libc vs Go's std lib vs mmap).

  scan hidden-lkms
    Look for hidden kernel modules.

  scan hidden-procs
    Look for hidden processes.
```



### TODO

- [ ] Add a cli option to scan the system with all the IOCs options.
- [ ] Read options from a configuration file.
- [ ] Dump logs in json and structured text.
- [ ] Add more options to scan for malicious lkms.
- [ ] Compare connections listed in /proc/net/* as well as the output of netstat/ss/lsof, with the connections found in kernel.
- [ ] Display what processes opened the existing sockets.

### Examples

#### Father (LD_PRELOAD rootkit)

https://github.com/mav8557/Father

* revealing hidden content (this malware hides `/etc/ld.so.preload`):
```bash
root@localhost:~# echo /lib/selinux.so.3 > /etc/ld.so.preload
root@localhost:~# cat /etc/ld.so.preload
cat: /etc/ld.so.preload: No such file or directory
root@localhost:~#
```

```bash
root@localhost:~# /home/ga/decloacker scan hidden-content /etc/ld.so.preload
decloacker v0.0, pid: 763609

[i] Checking for hidden content /etc/ld.so.preload

=== CONTENT WARNING (read) /etc/ld.so.preload ===
cat content:
 
-----------------------------------------------------------------
Go read content:
 /lib/selinux.so.3

====================================
root@localhost:~#
```

* unmasking hidden files/directories (by default, anything with "lobster" in the name):

```bash
root@localhost:~# ls /home/ga/rootkits/ld_preload/Father/*lobster*
ls: cannot access '/home/ga/rootkits/ld_preload/Father/*lobster*': No such file or directory
root@localhost:~#
```

Using Go's standard lib (i.e.: using syscalls directly, without libc):

```bash
root@localhost:~# /home/ga/decloacker scan hidden-files --recursive /home/ga/rootkits/ld_preload/Father/
decloacker v0.0, pid: 764851

[i] Checking hidden files ["/home/ga/rootkits/ld_preload/Father/"]

drwxrwxr-x	4096	2025-09-25T10:07:57+01:00	/home/ga/rootkits/ld_preload/Father/.git/logs/refs/remotes
-rw-rw-r--	0	2025-09-25T16:07:16+01:00	/home/ga/rootkits/ld_preload/Father/lobster/file2.txt
[w] 	HIDDEN: /home/ga/rootkits/ld_preload/Father/lobster/file2.txt

(...)

HIDDEN dirs/files found:

	drwxrwxr-x	4096	2025-09-25T16:07:16+01:00	/home/ga/rootkits/ld_preload/Father/lobster
	-rw-rw-r--	0	2025-09-25T16:07:16+01:00	/home/ga/rootkits/ld_preload/Father/lobster/file0.txt
	-rw-rw-r--	0	2025-09-25T16:07:16+01:00	/home/ga/rootkits/ld_preload/Father/lobster/file1.txt
	-rw-rw-r--	0	2025-09-25T16:07:27+01:00	/home/ga/rootkits/ld_preload/Father/lobster_test1.txt
	-rw-rw-r--	0	2025-09-25T16:07:16+01:00	/home/ga/rootkits/ld_preload/Father/lobster/file2.txt
	-rw-rw-r--	0	2025-09-25T16:07:16+01:00	/home/ga/rootkits/ld_preload/Father/lobster/file3.txt

[i] use decloacker cp <orig> <dest> to backup the files, or decloacker rm <path> to delete them

root@localhost:~#
```

```bash
root@localhost:~# rm /etc/ld.so.preload
rm: cannot remove '/etc/ld.so.preload': No such file or directory
root@localhost:~# /home/ga/decloacker rm /etc/ld.so.preload
decloacker v0.0, pid: 765449

[i] Deleting files [/etc/ld.so.preload]
	/etc/ld.so.preload:	OK
root@locahost:~#
```

### Resources

 - [User-space library rootkits revisited: Are user-space detection mechanisms futile?](https://arxiv.org/html/2506.07827v1)
 - [The Hidden Threat: Analysis of Linux Rootkit Techniques and Limitations of Current Detection Tools](https://dl.acm.org/doi/10.1145/3688808)
 - [Hiding Linux Processes with Bind Mounts](https://righteousit.com/2024/07/24/hiding-linux-processes-with-bind-mounts/)

