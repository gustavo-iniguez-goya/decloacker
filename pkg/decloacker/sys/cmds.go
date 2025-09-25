package sys

import (
	//"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/gustavo-iniguez-goya/decloacker/pkg/decloacker/log"
)

// functions to execute system commands like ps, ls, netstat, ... to obtain info
// from the system, and compare it against possible hidden data.

func parseLsLine(lastDir, line string) (string, string) {
	file := ""
	pth := strings.Trim(line, " \t")
	if pth == "" || pth == "." || pth == ".." {
		return lastDir, ""
	}
	if strings.HasSuffix(pth, ":") {
		pth = pth[0 : len(pth)-1]
	}
	if strings.HasSuffix(pth, "/") {
		pth = pth[0 : len(pth)-1]
	}
	if strings.HasPrefix(pth, "/") {
		lastDir = pth
	} else {
		file = path.Base(pth)
		if file == "." || file == ".." {
			return lastDir, ""
		}
		pth = file
		pth = lastDir + "/" + pth
	}
	return lastDir, pth
}

// Ls uses the system "ls" command to list the files of directories.
// find /tmp -type d
// ls /tmp -R -a
func Ls(tool, dir string, args ...string) map[string]fs.FileInfo {
	files := make(map[string]fs.FileInfo)
	if dir[len(dir)-1] == '/' {
		dir = dir[0 : len(dir)-1]
	}

	cmd := exec.Command(tool, args...)
	out, err := cmd.Output()
	if err != nil {
		log.Error("walkDir()", "ERROR listing dir: %s\n\n", err)
		return files
	}
	lastDir := dir
	pth := ""
	for _, line := range strings.Split(string(out), "\n") {
		lastDir, pth = parseLsLine(lastDir, line)
		if pth == "" {
			continue
		}
		fi, _ := os.Lstat(pth)
		files[pth] = fi
	}

	return files
}

// Cat uses the system cat command to read the content of a file
func Cat(tool string, paths ...string) map[string]string {
	procs := make(map[string]string)

	for _, p := range paths {
		out, err := exec.Command(tool, p).Output()
		if err != nil {
			procs[p] = ""
			continue
		}
		procs[p] = string(out)
	}

	return procs
}
