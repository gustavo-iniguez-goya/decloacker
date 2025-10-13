package utils

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/gustavo-iniguez-goya/decloaker/pkg/log"
)

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// we could use QuoteToASCII(), but find or ls don't escape unicode characters,
// so we leave as is.
func ToAscii(orig string) string {
	out := strconv.Quote(orig)
	return out[1 : len(out)-1]
}

func ReadlinkEscaped(path string) (string, error) {
	exe, err := os.Readlink(path)
	return ToAscii(exe), err
}

func StripLastSlash(dir string) string {
	if dir == "/" {
		return dir
	}
	if dir[len(dir)-1] == '/' {
		dir = dir[0 : len(dir)-1]
	}

	return dir
}

func ResetRootPath(dir string) string {
	if dir == "/" {
		return ""
	}
	return dir
}

func PrintFileExtendedInfo(st any) {
	statt, statok := st.(*syscall.Stat_t)
	if !statok {
		log.Debug("stat.Sys() not instance of syscall.Stat_t? review\n")
		return
	}
	log.Detection("\n\tSize: %d \tBlock size: %d \tBlocks: %d\n\tDevice: %d \tRdev: %d \tInode: %d \tLinks: %d\n\tUID: %d GID: %d\n\tAccess: %s\n\tModify: %s\n\tChange: %s\n\n",
		statt.Size,
		statt.Blksize,
		statt.Blocks,
		statt.Dev,
		statt.Rdev,
		statt.Ino,
		statt.Nlink,
		statt.Uid,
		statt.Gid,
		time.Unix(statt.Atim.Sec, statt.Atim.Nsec),
		time.Unix(statt.Mtim.Sec, statt.Mtim.Nsec),
		time.Unix(statt.Ctim.Sec, statt.Ctim.Nsec),
	)

}

func ExpandPaths(pathList []string) []string {
	paths := []string{}
	for _, p := range pathList {
		ps, err := filepath.Glob(p)
		if err != nil {
			continue
		}
		paths = append(paths, ps...)
	}

	return paths
}
