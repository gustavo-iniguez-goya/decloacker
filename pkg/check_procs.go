package decloacker

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/gustavo-iniguez-goya/decloacker/pkg/ebpf"
	"github.com/gustavo-iniguez-goya/decloacker/pkg/log"
)

const (
	PidName = 0
	PidPID  = 5
	PidPPID = 6

	ProcPrefix = "/proc/"
	ProcMounts = "/proc/mounts"
	ProcPidMax = "/proc/sys/kernel/pid_max"
)

var (
	reStatusField = regexp.MustCompile(`([A-Za-z]+):\t(.*)\n`)
)

func printHiddenPid(pid, ppid, inode, uid, gid, comm, exe string) {
	log.Detection("\tPID: %s\tPPid: %s\n\tInode: %s\tUid: %s\tGid: %s\n\tComm: %s\n\tPath: %s\n\n",
		pid,
		ppid,
		inode,
		uid,
		gid,
		comm,
		exe,
	)
}

func getPidInfo(procPath string) ([][]string, string, error) {
	statusContent, err := os.ReadFile(procPath + "/status")
	if err != nil {
		return nil, "", err
	}
	status := reStatusField.FindAllStringSubmatch(string(statusContent), -1)
	var exe string
	exe, err = os.Readlink(procPath + "/exe")
	if err != nil {
		exe = "(unable to read process path, maybe a kernel thread)"
	}
	if len(status) == 0 {
		err = fmt.Errorf("unable to read %s content", procPath)
	}

	return status, exe, nil
}

func bruteForcePids(expected map[string]os.FileInfo) int {
	ret := OK

	hiddenProcs := make(map[int]string)
	pidMaxTmp, _ := os.ReadFile(ProcPidMax)
	pidMax, err := strconv.Atoi(string(bytes.Trim(pidMaxTmp, "\n")))
	if pidMax == 0 {
		log.Debug("/proc/sys/kernel/pid_max should not be 0 (error? %s)", err)
		pidMax = 4194304 // could be less
	}

	log.Info("trying with brute force (pid max: %d):\n", pidMax)

	procPath := ""
	for pid := 1; pid < pidMax; pid++ {
		procPath = fmt.Sprint(ProcPrefix, pid)
		if _, found := expected[procPath]; found {
			continue
		}
		err := os.Chdir(procPath)
		statInf := Stat([]string{procPath})
		chdirWorked := err == nil
		statWorked := len(statInf) > 0

		procPath = fmt.Sprint(ProcPrefix, pid, "/status")
		status, err := os.ReadFile(procPath)
		if err != nil {
			if chdirWorked {
				log.Detection("\tWARNING: proc found via Chdir: %d\n", pid)
				ret = PROC_HIDDEN
			}
			if statWorked {
				log.Detection("\tWARNING: PID found via Stat: %d\n", pid)
				PrintStat([]string{procPath})
				ret = PROC_HIDDEN
			}

			continue
		}
		// exclude threads?
		if !bytes.Contains(status, []byte(
			fmt.Sprint("Tgid:\t", pid),
		)) {
			log.Debug("excluding pid %d, possible thread\n", pid)
			continue
		}

		procPath = fmt.Sprint(ProcPrefix, pid, "/comm")
		comm, _ := os.ReadFile(procPath)
		procPath = fmt.Sprint(ProcPrefix, pid, "/cmdline")
		cmdline, err := os.ReadFile(procPath)
		procPath = fmt.Sprint(ProcPrefix, pid, "/exe")
		exe, _ := os.Readlink(procPath)
		hiddenProcs[pid] = exe

		log.Detection("WARNING: hidden proc? /proc/%d\n", pid)
		log.Detection("\n\texe: %s\n\tcomm: %s\n\tcmdline: %s\n\n", exe, bytes.Trim(comm, "\n"), cmdline)

		ret = PROC_HIDDEN
	}

	if len(hiddenProcs) == 0 && ret == OK {
		log.Info("No hidden processes found using brute force\n\n")
	}

	return ret
}

// CheckBindMounts looks for PIDs hidden with bind mounts.
func CheckBindMounts() int {
	ret := OK
	printPid := func(procPathB []byte) {
		procPath := string(procPathB)
		status, exe, err := getPidInfo(procPath)
		if err != nil {
			return
		}
		log.Detection("\tOverlay PID:\n\t  PID: %s\n\t  PPid: %s\n\t  Comm: %s\n\t  Path: %s\n\n",
			status[PidPID][2],
			status[PidPPID][2],
			status[PidName][2],
			exe,
		)

		err = exec.Command("umount", procPath).Run()
		if err != nil {
			log.Error("unable to umount %s to unhide the PID\n", procPath)
			return
		}
		log.Debug("%s umounted\n", procPath)

		status, exe, err = getPidInfo(procPath)
		log.Detection("\tHIDDEN PID:\n\t  PID: %s\n\t  PPid: %s\n\t  Comm: %s\n\t  Path: %s\n\n",
			status[PidPID][2],
			status[PidPPID][2],
			status[PidName][2],
			exe,
		)
	}

	mounts, err := os.ReadFile(ProcMounts)
	if err != nil {
		log.Error("mounted pid: %s", err)
	} else {
		mountsRe := regexp.MustCompile(`\/proc\/[0-9]+`)
		if matches := mountsRe.FindAll(mounts, -1); matches != nil {
			ret = PID_BIND_MOUNT
			for n, m := range matches {
				log.Detection("%d - WARNING, pid hidden under another pid (mount): %s\n", n, m)
				printPid(m)
			}
			log.Log("\n")
		}
	}

	return ret
}

func CheckHiddenProcs(doBruteForce bool) int {
	log.Info("Checking hidden processes:\n\n")

	ret := OK
	retBrute := OK
	retBind := CheckBindMounts()

	orig, expected := ListFiles("/proc", "ls", false)
	ret = CompareFiles(orig, expected)

	liveTasks := ebpf.GetPidList("")
	for _, t := range liveTasks {
		procPath := ProcPrefix + t.Pid
		if procPath == ourProcPath {
			continue
		}

		if _, found := orig[procPath]; found {
			continue
		}

		log.Detection("WARNING (ebpf): pid hidden?\n")

		printHiddenPid(t.Pid, t.PPid, t.Inode, t.Uid, t.Gid, t.Comm, t.Exe)
		statInf := Stat([]string{procPath})
		if len(statInf) > 0 {
			log.Detection("\tPID confirmed via Stat: %s, %s\n\n", t.Pid, t.Comm)
			PrintStat([]string{procPath})
		}
		ret = PROC_HIDDEN
	}

	if doBruteForce {
		retBrute = bruteForcePids(expected)
	}

	if ret != OK || retBind != OK || retBrute != OK {
		log.Warn("hidden processes found.\n\n")
		if retBind != OK {
			ret = retBind
		}
		if retBrute != OK {
			ret = retBrute
		}
	}
	if ret == OK {
		log.Info("No hidden processes found. You can try it with \"decloacker scan hidden-procs --brute-force\"\n\n")
	}

	return ret
}
