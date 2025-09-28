package decloacker

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/gustavo-iniguez-goya/decloacker/pkg/decloacker/log"
)

// CheckBindMounts looks for PIDs hidden with bind mounts.
func CheckBindMounts() int {
	ret := OK
	printPid := func(pid []byte) {
		statRogue, err := os.ReadFile(fmt.Sprint(string(pid), "/stat"))
		if err != nil {
			return
		}
		fields := bytes.Fields(statRogue)
		overlayPid := fields[0]
		log.Detection("\tHidden PID: %s, %s\n", pid, fields[1])
		statOverlay, err := os.ReadFile(fmt.Sprint("/proc/", string(overlayPid), "/stat"))
		if err != nil {
			log.Error("%s", err)
			return
		}
		fields = bytes.Fields(statOverlay)
		if len(fields) > 1 {
			log.Detection("\tOverlay PID: /proc/%s, %s\n", overlayPid, fields[1])
		}
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
	ret = CheckBindMounts()

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
		if len(hiddenProcs) == 0 {
			log.Info("No hidden processes found. You can try it with \"decloacker scan hidden-procs --brute-force\"\n")
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
	if len(hiddenProcs) == 0 {
		log.Info("No hidden processes found using brute force\n")
	}

	return ret
}
