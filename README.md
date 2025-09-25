# decloacker
a simple tool to reveal files, directories and connections hidden by malware.

### TODO

- [ ] Add a cli option to scan the system with all the IOCs options.
- [ ] Read options from a configuration file.
- [ ] Dump logs in json and structured text.
- [ ] Add more options to scan for malicious lkms.

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

[i] use decloacker disk cp <orig> <dest> to backup the files, or decloacker disk rm <path> to delete them

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
