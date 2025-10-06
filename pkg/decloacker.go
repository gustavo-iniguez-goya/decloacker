package decloacker

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"strconv"
	"syscall"

	"github.com/gustavo-iniguez-goya/decloacker/pkg/log"
	"github.com/gustavo-iniguez-goya/decloacker/pkg/sys"
)

var (
	ourPid      = strconv.Itoa(os.Getpid())
	ourProcPath = "/proc/" + ourPid
)

// common functions to list or read files/directories by using Go's standard library
// (i.e.: without using libc's functions).

func Stat(paths []string) map[string]os.FileInfo {
	fileDetails := make(map[string]os.FileInfo)

	for _, p := range paths {
		stat, err := os.Stat(p)
		if err != nil {
			log.Debug("Unable to stat %s: %s\n", p, err)
			continue
		}
		fileDetails[p] = stat
	}

	return fileDetails
}

func Cat(paths []string) int {
	log.Info("Cat file %v\n", paths)

	for _, p := range paths {
		content, err := ioutil.ReadFile(p)
		if err != nil {
			log.Error("Unable to read file %s: %s\n", p, err)
			continue
		}
		log.Info("%s:\n\n", p)
		log.Detection("%s", content)
		log.Separator()
	}
	log.Log("\n")

	return OK
}

func Copy(orig, dest string) int {
	log.Info("Copying file %s -> %s ...\n", orig, dest)

	data, err := ioutil.ReadFile(orig)
	if err != nil {
		log.Error("Copy: %s\n", err)
		return ERROR
	}
	fi, err := os.Stat(orig)
	if err != nil {
		log.Error("Error stat-ing file: %s\n", err)
		return ERROR
	}
	err = ioutil.WriteFile(dest, data, fi.Mode().Perm())
	if err != nil {
		log.Error("unable to copy %s: %s\n", orig, err)
		return ERROR
	}
	log.Ok("Ok\n\n")

	return OK
}

func Delete(paths []string) int {
	log.Info("Deleting files %s\n", paths)
	ret := OK
	for _, p := range paths {
		if err := os.Remove(p); err != nil {
			log.Error("%s\n", err)
			ret = ERROR
			continue
		}
		log.Ok("%s\n", p)
	}

	return ret
}

func Rename(orig, dest string) int {
	log.Info("Renaming file %s -> %s\t", orig, dest)
	if err := os.Rename(orig, dest); err != nil {
		log.Error("Error removing %s", err)
		return ERROR
	}
	log.Log("OK\n")
	return OK
}

func MmapFile(path string) (int64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Get file size
	info, err := file.Stat()
	if err != nil {
		return 0, "", fmt.Errorf("failed to stat file: %v", err)
	}
	size := info.Size()

	// Memory-map the file
	data, err := syscall.Mmap(
		int(file.Fd()),     // file descriptor
		0,                  // offset
		int(size),          // length
		syscall.PROT_READ,  // memory protection
		syscall.MAP_SHARED, // flags
	)
	if err != nil {
		return 0, "", fmt.Errorf("failed to mmap file: %v", err)
	}

	defer func() {
		if err := syscall.Munmap(data); err != nil {
			log.Warn("failed to unmap: %v", err)
		}
	}()

	return size, string(data), nil
}

func ReadDir(path string, recursive bool) map[string]fs.FileInfo {
	list := make(map[string]fs.FileInfo)
	//list[path] = nil
	//Debug("readDir() %v\n", list)

	if recursive {
		root := os.DirFS(path)
		path = resetRootPath(path)
		fs.WalkDir(root, ".", func(path2 string, d fs.DirEntry, err error) error {
			if path2 == "." || path2 == ".." {
				return nil
			}
			if err != nil {
				log.Error("error reading path %s: %s\n", path2, err)
				return nil
			}
			path2 = path + "/" + path2
			info, err := d.Info()
			list[path2] = info

			return nil
		})
		return list
	}

	entries, _ := os.ReadDir(path)
	path = resetRootPath(path)
	for _, entry := range entries {
		inf, _ := entry.Info()
		//log.Debug("readDir() %s\n", path+"/"+entry.Name())
		list[path+"/"+entry.Name()] = inf
	}

	return list
}

// ListFiles returns a list of files and directories using a system command like
// ls or find, and using Go's functions.
func ListFiles(path string, tool string, deep bool) (map[string]os.FileInfo, map[string]os.FileInfo) {
	path = stripLastSlash(path)

	args := []string{path}
	if !deep {
		args = append(args, []string{"-maxdepth", "1"}...)
	}
	if tool == sys.CmdLs {
		args = []string{path, "-A"} //, "--format=single-column"}
		if deep {
			args = append(args, []string{"-R"}...)
		}
	}

	log.Debug("Listing files with system commands ... \n")
	lsDirs := make(map[string]fs.FileInfo)
	if tool == sys.CmdLs {
		lsDirs = sys.Ls(path, args...)
	} else {
		lsDirs = sys.Find(path, args...)
	}
	log.Debug("Listing files with decloacker ... \n")
	list := ReadDir(path, deep)

	return lsDirs, list
}
