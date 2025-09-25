package decloacker

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	//"log"
	//"net"
	"os"
	"syscall"
	//"time"

	//"github.com/gustavo-iniguez-goya/decloacker"
	"github.com/gustavo-iniguez-goya/decloacker/pkg/decloacker/log"
	"github.com/gustavo-iniguez-goya/decloacker/pkg/decloacker/sys"
)

// common functions to list or read files/directories by using Go's standard library
// (i.e.: without using libc's functions).

func Cat(paths []string) int {
	log.Info("Cat file %v\n", paths)

	for _, p := range paths {
		content, err := ioutil.ReadFile(p)
		if err != nil {
			log.Error("Unable to read file %s: %s\n", p, err)
			continue
		}
		log.Info("%s:\n\n", p)
		log.Log("%s", content)
		log.Separator()
	}
	log.Log("\n")

	return OK
}

func Copy(orig, dest string) int {
	log.Info("Copying file %s -> %s:\t", orig, dest)

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
	log.Info("OK\n\n")

	return OK
}

func Delete(paths []string) int {
	log.Info("Deleting files %s\n", paths)
	ret := OK
	for _, p := range paths {
		log.Log("\t%s:", p)
		if err := os.Remove(p); err != nil {
			log.Error("Error removing %s: %s\n", p, err)
			ret = ERROR
			continue
		}
		log.Log("\tOK\n")
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
		fs.WalkDir(root, ".", func(path2 string, d fs.DirEntry, err error) error {
			if err != nil {
				log.Error("walkdir err:", err)
				return nil
			}
			if path2 == "." || path2 == ".." {
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
	for _, entry := range entries {
		inf, _ := entry.Info()
		//Debug("readDir() %s\n", path+"/"+entry.Name())
		list[path+"/"+entry.Name()] = inf
	}
	return list
}

func LsFiles(path string, deep bool) (map[string]os.FileInfo, map[string]os.FileInfo) {
	cmd := "ls"
	args := []string{path}
	args = append(args, []string{"-a"}...)
	if deep {
		log.Debug("Recursive scanning enabled\n\n")
		args = append(args, []string{"-R"}...)
	}

	lsDirs := sys.Ls(cmd, path, args...)
	list := make(map[string]fs.FileInfo)

	if path[len(path)-1] == '/' {
		path = path[0 : len(path)-1]
	}
	list = ReadDir(path, deep)

	return lsDirs, list
}
