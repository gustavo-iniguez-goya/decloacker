package decloacker

import (
	"bytes"
	"fmt"
	"os"
	"strconv"

	"github.com/gustavo-iniguez-goya/decloacker/pkg/decloacker/log"
)

func CheckHiddenProcs() int {
	log.Info("Checking hidden processes:\n\n")

	ret := OK
	pidMaxTmp, _ := os.ReadFile("/proc/sys/kernel/pid_max")
	pidMax, _ := strconv.Atoi(string(bytes.Trim(pidMaxTmp, "\n")))
	hiddenProcs := make(map[int]string)

	orig, expected := LsFiles("/proc", false)
	ret = CompareFiles(orig, expected)

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
		log.Info("No hidden processes found with this technique\n")
	}

	return ret
}
