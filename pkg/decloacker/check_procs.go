package decloacker

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/gustavo-iniguez-goya/decloacker/pkg/decloacker/log"
)

const (
	PidName = 0
	PidPID  = 5
	PidPPID = 6
)

var (
	reStatusField = regexp.MustCompile(`([A-Za-z]+):\t(.*)\n`)
)

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

	return status, exe, nil
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

		// TODO: umount procPath
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

	mounts, err := os.ReadFile("/proc/mounts")
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
	retBind := CheckBindMounts()

	hiddenProcs := make(map[int]string)
	pidMaxTmp, _ := os.ReadFile("/proc/sys/kernel/pid_max")
	pidMax, err := strconv.Atoi(string(bytes.Trim(pidMaxTmp, "\n")))
	if pidMax == 0 {
		log.Debug("/proc/sys/kernel/pid_max should not be 0 (error? %s)", err)
		pidMax = 4194304 // could be less
	}

	orig, expected := ListFiles("/proc", "ls", false)
	ret = CompareFiles(orig, expected)

	if !doBruteForce {
		if len(hiddenProcs) == 0 && ret == OK && retBind == OK {
			log.Info("No hidden processes found. You can try it with \"decloacker scan hidden-procs --brute-force\"\n\n")
		}
		return ret
	}
	log.Info("trying with brute force (pid max: %d):\n", pidMax)

	procPath := ""
	for pid := 1; pid < pidMax; pid++ {
		procPath = fmt.Sprint("/proc/", pid)
		if _, found := expected[procPath]; found {
			continue
		}
		procPath = fmt.Sprint("/proc/", pid, "/status")
		status, err := os.ReadFile(procPath)
		if err != nil {
			continue
		}
		// exclude threads?
		if !bytes.Contains(status, []byte(
			fmt.Sprint("Tgid:\t", pid),
		)) {
			log.Debug("excluding pid %d, possible thread\n", pid)
			continue
		}

		procPath = fmt.Sprint("/proc/", pid, "/comm")
		comm, _ := os.ReadFile(procPath)
		procPath = fmt.Sprint("/proc/", pid, "/cmdline")
		cmdline, err := os.ReadFile(procPath)
		procPath = fmt.Sprint("/proc/", pid, "/exe")
		exe, _ := os.Readlink(procPath)
		hiddenProcs[pid] = exe

		log.Detection("WARNING: hidden proc? /proc/%d\n", pid)
		log.Detection("\n\texe: %s\n\tcomm: %s\n\tcmdline: %s\n\n", exe, bytes.Trim(comm, "\n"), cmdline)
	}

	if len(hiddenProcs) == 0 && ret == OK && retBind == OK {
		log.Info("No hidden processes found using brute force\n\n")
	}

	return ret
}
