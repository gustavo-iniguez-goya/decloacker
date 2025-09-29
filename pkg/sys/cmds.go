package sys

import (
	//"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/gustavo-iniguez-goya/decloacker/pkg/log"
)

var (
	CmdFind = "find"
	CmdLs   = "ls"
)

// functions to execute system commands like ps, find, ls, netstat, ... to obtain info
// from the system, and compare it against possible hidden data.

// parseLsLine parses the output of ls -A -R /path:
// /path:
// file1 file2 file3
func parseLsLine(lastDir, line string) (string, string) {
	if line == "" {
		return lastDir, ""
	}

	pth := strings.Trim(line, " \t")
	// new directory:
	// /tmp/decloacker/pkg/disk:
	// disk.go
	// files and directories may end with ":", so we need to check that i starts with "/"
	if strings.HasPrefix(pth, "/") && strings.HasSuffix(pth, ":") {
		pth = pth[0 : len(pth)-1]
		return pth, pth
	}
	file := path.Base(pth)
	pth = file
	if lastDir == "/" {
		pth = lastDir + pth
	} else {
		pth = lastDir + "/" + pth
	}
	return lastDir, pth
}

// Ls uses the system "ls" command to list the files of directories.
// ls /tmp -R -a
func Ls(dir string, args ...string) map[string]fs.FileInfo {
	files := make(map[string]fs.FileInfo)
	cmd := exec.Command(CmdLs, args...)
	out, err := cmd.Output()
	if err != nil {
		log.Error("error listing files %s\n\n", dir)
		return files
	}
	lastDir := dir
	pth := ""
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		lastDir, pth = parseLsLine(lastDir, line)
		if pth == "" {
			continue
		}
		fi, _ := os.Lstat(pth)
		files[pth] = fi
	}
	delete(files, dir)

	return files
}

// Find uses the command "find" to find files and directories
func Find(dir string, args ...string) map[string]fs.FileInfo {
	files := make(map[string]fs.FileInfo)
	// Follow symbolic links when parsing the cmdline, otherwise scanning a symlink
	// that points to a directory returns just the directory.
	args = append([]string{"-H"}, args...)

	cmd := exec.Command(CmdFind, args...)
	out, err := cmd.Output()
	if err != nil {
		log.Error("error listing files %s\n\n", dir)
		return files
	}
	lines := strings.Split(string(out), "\n")
	idx := len(lines) - 1
	// the last line of "find" adds a '\n', so when splitting the output by newline,
	// it always adds an empty line.
	lines = append(lines[:idx], lines[idx+1:]...)
	for _, line := range lines {
		fi, _ := os.Lstat(line)
		files[line] = fi
	}
	delete(files, dir)

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
