package decloacker

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/diskfs/go-diskfs"
	//"github.com/diskfs/go-diskfs/disk"
	//"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/filesystem/ext4"
	"github.com/gustavo-iniguez-goya/decloacker/pkg/log"
)

// functions to read files directly from the disk device.

func ReadDir(dev string, partition int, path string, openMode diskfs.OpenModeOption) map[string]os.FileInfo {
	if path[len(path)-1] == '/' {
		path = path[0 : len(path)-1]
	}

	list := make(map[string]os.FileInfo)
	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(openMode),
	)
	if err != nil {
		log.Error("unable to read disk %s\n", dev)
		return list
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		log.Error("unable to read disk partition %s, %d: %s\n", dev, partition, err)
		return list
	}

	ext4fs, ok := fs.(*ext4.FileSystem)
	if !ok {
		log.Error("%s is not a ext4 filesystem\n")
		return list
	}
	defer ext4fs.Close()

	WalkPath(ext4fs, path, "",
		func(dir string, entries []os.FileInfo) {
			log.Debug("reading path %s\n", dir)
			for _, e := range entries {
				if e.Name() == "." || e.Name() == ".." {
					continue
				}
				list[dir+"/"+e.Name()] = e
				log.Log("%v\t%d\t%s\t%s\n", e.Mode(), e.Size(), e.ModTime().Format(time.RFC3339), e.Name())
			}
		})
	if err != nil {
		log.Warn("listDiskFiles warning: %s\n", err)
	}

	return list
}

func WalkPath(fs *ext4.FileSystem, path string, sep string, callback func(string, []os.FileInfo)) error {
	//Log("reading dir %s\n\n", path)
	entries, err := fs.ReadDir(path)
	if err != nil {
		return err
	}
	callback(path, entries)

	for _, e := range entries {
		if e.Name() == "." || e.Name() == ".." {
			continue
		}
		fullPath := path + "/" + e.Name()
		if e.IsDir() {
			WalkPath(fs, fullPath, sep, callback)
			continue
		}
	}

	return nil
}

// https://pkg.go.dev/github.com/diskfs/go-diskfs@v1.7.0/filesystem#FileSystem
func Cp(dev string, partition int, orig, dest string, openMode diskfs.OpenModeOption) error {
	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(openMode),
	)
	if err != nil {
		return fmt.Errorf("unable to read disk, %s", err)
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		return fmt.Errorf("unable to read disk partition %s, %d, %s", dev, partition, err)
	}

	ext4fs, ok := fs.(*ext4.FileSystem)
	if !ok {
		return fmt.Errorf("%s, partition %d, is not a ext4 filesystem", dev, partition)
	}
	defer ext4fs.Close()

	f, err := ext4fs.OpenFile(orig, os.O_RDONLY)
	if err != nil {
		return fmt.Errorf("ext4.OpenFile() %s", err)
	}

	out, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("os.Create() %s", err)
	}
	defer out.Close()

	if _, err = io.Copy(out, f); err != nil {
		return fmt.Errorf("io.Copy() %s", err)
	}
	err = out.Sync()

	return err
}

func Mv(dev string, partition int, orig, dest string, openMode diskfs.OpenModeOption) error {
	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(openMode),
	)
	if err != nil {
		return fmt.Errorf("unable to read disk, %s", err)
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		return fmt.Errorf("unable to read disk partition %s, %d, %s", dev, partition, err)
	}

	ext4fs, ok := fs.(*ext4.FileSystem)
	if !ok {
		return fmt.Errorf("%s, partition %d, is not a ext4 filesystem", dev, partition)
	}
	defer ext4fs.Close()

	err = ext4fs.Rename(orig, dest)
	if err != nil {
		return fmt.Errorf("renme/move error: %s", err)
	}

	return err
}

// XXX: considered dangerous??
// everytime a file is deleted, it causes inconsistencies on ext4 filesystemsthe system complains on bad sectors, etc
func Rm(dev string, partition int, paths []string, openMode diskfs.OpenModeOption) error {
	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(openMode),
	)
	if err != nil {
		return fmt.Errorf("unable to read disk, %s", err)
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		return fmt.Errorf("unable to read disk partition %s, %d, %s", dev, partition, err)
	}

	ext4fs, ok := fs.(*ext4.FileSystem)
	if !ok {
		return fmt.Errorf("%s, partition %d, is not a ext4 filesystem", dev, partition)
	}
	defer ext4fs.Close()

	var er error
	for _, p := range paths {
		log.Info("removing %s: ", p)
		err := ext4fs.Remove(p)
		if err != nil {
			er = err
			log.Log("%s (verify that the path is a ext4 filesystem)\n", err)
		} else {
			log.Info("OK\n")
		}
	}
	if er != nil {
		er = fmt.Errorf("unable to copy some paths")
	}

	return err
}

func Info(dev string, partition int, paths []string, openMode diskfs.OpenModeOption) ([]os.FileInfo, error) {
	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(openMode),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read disk, %s", err)
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		return nil, fmt.Errorf("unable to read disk partition %s, %d, %s", dev, partition, err)
	}

	ext4fs, ok := fs.(*ext4.FileSystem)
	if !ok {
		return nil, fmt.Errorf("%s:%d is not a ext4 filesystem", dev, partition)
	}
	defer ext4fs.Close()

	var list []os.FileInfo
	for _, p := range paths {
		stat, err := ext4fs.Stat(p)
		if err != nil {
			log.Error("ext4.Stat() %s\n", err)
			continue
		}
		list = append(list, stat)
	}

	return list, nil
}

func ReadFile(dev string, partition int, path string) ([]byte, error) {
	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(diskfs.ReadOnly),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read disk, %s", err)
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		return nil, fmt.Errorf("unable to read disk partition %s, %d, %s", dev, partition, err)
	}

	ext4fs, ok := fs.(*ext4.FileSystem)
	if !ok {
		return nil, fmt.Errorf("%s:%d is not a ext4 filesystem", dev, partition)
	}
	defer ext4fs.Close()

	fd, err := ext4fs.OpenFile(path, os.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("ext4.Open() %s\n", err)
	}
	defer fd.Close()

	scanner := bufio.NewReader(fd)
	content := []byte{}
	for {
		line, err := scanner.ReadBytes('\n')
		if err != nil || err == io.EOF {
			break
		}
		content = append(content, line...)
	}

	return content, nil
}
