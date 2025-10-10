# decloaker

<p align="center">a simple tool to reveal files, directories and connections hidden by malware.</p>

<p align="center">
    <img width="250" height="250" alt="decloacker3" src="https://github.com/user-attachments/assets/6f052933-47fe-4784-b34c-3338e0b28fa0" /> 
</p>

<p align="center">•• <a href="#usage">Usage</a> • <a href="#malware-analysis-examples">Malware analysis examples</a> • <a href="#todo">TODO</a> • <a href="#resources">Resources</a> ••</p>

### Usage

tl;dr: `./bin/decloaker --help`

There're 4 main areas:

cat, list, move, delete or copy files without the libc.
  - Useful for LD_PRELOAD based rootkits.

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

List, copy or get info of directories and files by accessing directly the disk device (only ext4 filesystems).

   - These options help to manipulate files or directories hidden by some kernel rootkits (like Diamorphine).
   - NOTE: only available for ext4 filesystems.
   - NOTE: this feature does not work on tmpfs, so if /tmp is mounted on tmpfs, it won't find hidden files/directories.
     it'll work for LD_PRELOAD rootkits, and some kernel rootkits.


```bash
  disk ls --dev=STRING <paths> ... [flags]
    List directories and files by reading directly from the disk device

  disk cp --dev=STRING <orig> <dest> [flags]
    Copy directories and files directly from the disk device

  disk stat --dev=STRING <paths> ... [flags]
    Return information about a path

  disk cat --dev=STRING <path> [flags]
    Reads the content of a file and prints it to stdout
```

Scan the system to unhide files, directories, processes or kernel rootkits.
   
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

Dump connections, processes, opened files or kernel modules directly from the kernel, without parsing /proc/*:

```bash
  netstat [<protos> ...] [flags]
    List connections from kernel via netlink.

  conntrack list
    Dump conntrack connections table from kernel.

  dump files [flags]
    Dump opened files.

  dump kmods
    Dump loaded kernel modules.

  dump tasks [flags]
    Dump running tasks (processes).
```


### TODO

- [ ] Add a cli option to scan the system with all the IOCs options.
- [ ] Read options from a configuration file.
- [ ] Dump logs in json and structured text.
- [ ] Compare connections listed in /proc/net/* as well as the output of netstat/ss/lsof, with the connections found in kernel.
- [ ] Display the differences when scanning with `scan hidden-content`.
- [x] Display what processes opened the existing sockets.
      - 1/2 done: does not work for connections opened in containers.

- [ ] Scan eBPF modules.

### Malware analysis examples

More analyses here: https://github.com/gustavo-iniguez-goya/decloaker/discussions/categories/malware-analysis

#### Father (LD_PRELOAD rootkit)

https://github.com/mav8557/Father

Revealing hidden content (this malware hides `/etc/ld.so.preload`):

```bash
root@localhost:~# echo /lib/selinux.so.3 > /etc/ld.so.preload
root@localhost:~# cat /etc/ld.so.preload
cat: /etc/ld.so.preload: No such file or directory
root@localhost:~#
```

```bash
root@localhost:~# /home/ga/decloaker scan hidden-content /etc/ld.so.preload
decloaker v0.0, pid: 763609

[i] Checking for hidden content /etc/ld.so.preload

=== CONTENT WARNING (read) /etc/ld.so.preload ===
cat content:
 
-----------------------------------------------------------------
Go read content:
 /lib/selinux.so.3

====================================
root@localhost:~#
```

Unmasking hidden files/directories (by default, anything with "lobster" in the name):

```bash
root@localhost:~# ls /home/ga/rootkits/ld_preload/Father/*lobster*
ls: cannot access '/home/ga/rootkits/ld_preload/Father/*lobster*': No such file or directory
root@localhost:~#
```

Using Go's standard lib (i.e.: using syscalls directly, without libc):

```bash
root@localhost:~# /home/ga/decloaker scan hidden-files --recursive /home/ga/rootkits/ld_preload/Father/
decloaker v0.0, pid: 764851

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

[i] use decloaker cp <orig> <dest> to backup the files, or decloaker rm <path> to delete them

root@localhost:~#
```

```bash
root@localhost:~# rm /etc/ld.so.preload
rm: cannot remove '/etc/ld.so.preload': No such file or directory
root@localhost:~# /home/ga/decloaker rm /etc/ld.so.preload
decloaker v0.0, pid: 765449

[i] Deleting files [/etc/ld.so.preload]
	/etc/ld.so.preload:	OK
root@locahost:~#
```

#### Diamorphine (kernel rootkit)

By default, it hides files or directories with "diamorphine_secret" in the name:

```bash
root@localhost:~# ls /home/ga/Diamorphine/
diamorphine.c	diamorphine.mod    diamorphine.o	   LICENSE.txt	  Module.symvers
diamorphine.h	diamorphine.mod.c  ***diamorphine_secret***	   Makefile	  README.md
diamorphine.ko	diamorphine.mod.o  ***diamorphine_secret.txt***  modules.order
root@localhost:~#
```

It can also hide processes, by sending them the signal `-31`. We'll hide these processes later:

```bash

root@localhost:~# sleep 99999 &
[1] 1093
root@localhost:~# sleep 99999 &
[1] 1094
root@localhost:~# pgrep sleep
1093
1094
root@localhost:~#
```

Load the rootkit, and verify that the files and directories with "diamorphine_secret" are gone:

```bash
root@localhost:~# insmod /home/ga/Diamorphine/diamorphine.ko 
```

```bash
root@localhost:~# ls /home/ga/Diamorphine/
diamorphine.c  diamorphine.ko	diamorphine.mod.c  diamorphine.o  Makefile	 Module.symvers
diamorphine.h  diamorphine.mod	diamorphine.mod.o  LICENSE.txt	  modules.order  README.md
root@localhost:~#
```

Try to list the files with decloaker `disk ls` tool:

```bash
root@localhost:~# /home/ga/decloaker --log-level detection disk ls -d /dev/sda1 /home/ga/Diamorphine/

HIDDEN dirs/files found:

	----------	0	2025-09-25T11:53:45+01:00	/home/ga/Diamorphine/diamorphine_secret.txt
	----------	4096	2025-09-25T11:53:51+01:00	/home/ga/Diamorphine/diamorphine_secret
	----------	0	2025-09-25T11:53:51+01:00	/home/ga/Diamorphine/diamorphine_secret/file_hidden.txt
root@localhost:~#
```

Now we'll hide the processes:

```bash
root@localhost:~# kill -31 1093
root@localhost:~# kill -31 1094
root@localhost:~# pgrep -a sleep
root@localhost:~# 
root@localhost:~# ls /proc/|grep 2374
root@localhost:~# ls /proc/|grep 756572
root@localhost:~#
```

Let's try to unhide these processes:

```bash
root@localhost:~# /home/ga/decloaker scan hidden-procs
decloaker v0.0, pid: 763693

[i] Checking hidden processes:

(...)

[i] 	files checked (140/139)
[i] 	no hidden dirs/files found

[i] trying with brute force (pid max: 4194304):
WARNING: hidden proc? /proc/1093

	exe: /usr/bin/sleep
	comm: sleep
	cmdline: sleep99999

WARNING: hidden proc? /proc/1094

	exe: /usr/bin/sleep
	comm: sleep
	cmdline: sleep99999

root@localhost:~#
```

This rootkit also hides itself from the system:

```bash
root@localhost:~# grep diamorphine /proc/modules
root@localhost:~#
```

See if we can reveal it:

```bash
root@localhost:~# /home/ga/decloaker scan hidden-lkms
decloaker v0.0, pid: 763715

[i] Checking kernel integrity
WARNING: kernel tainted
	(E) unsigned module loaded on a kernel that supports module signatures
	(O) externally-built ('out-of-tree') module was loaded


[i] Checking loaded kernel modules
tainted: d diamorphine/, OE

	WARNING: "diamorphine" kmod HIDDEN from /proc/modules

root@localhost:~# 
```

You can also use `decloaker disk --dev=/dev/sda1 cp /path/to/hidden_file.txt hidden_file_backup.txt` (only for ext4 filesystems).

### Resources

 - [User-space library rootkits revisited: Are user-space detection mechanisms futile?](https://arxiv.org/html/2506.07827v1)
 - [The Hidden Threat: Analysis of Linux Rootkit Techniques and Limitations of Current Detection Tools](https://dl.acm.org/doi/10.1145/3688808)
 - [Linux rootkits explained – Part 1: Dynamic linker hijacking](https://www.wiz.io/blog/linux-rootkits-explained-part-1-dynamic-linker-hijacking)
 - [Linux rootkits explained – Part 2: Loadable kernel modules](https://www.wiz.io/blog/linux-rootkits-explained-part-2-loadable-kernel-modules#detecting-lkm-rootkits-85)
 - [In-Depth Study of Linux Rootkits: Evolution, Detection, and Defense](https://www.first.org/resources/papers/amsterdam25/FIRST_Amsterdam_2025_Linux_Rootkits.pdf)
 - [Sandfly Security's articles on Linux forensics and malware](https://sandflysecurity.com/blog/tag/linux-forensics)
 - [Hiding Linux Processes with Bind Mounts](https://righteousit.com/2024/07/24/hiding-linux-processes-with-bind-mounts/)
 - [How is /proc able to list process IDs](https://ops.tips/blog/how-is-proc-able-to-list-pids/)
