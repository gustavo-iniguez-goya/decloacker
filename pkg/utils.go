package decloacker

import (
	"syscall"
	"time"

	"github.com/gustavo-iniguez-goya/decloacker/pkg/log"
)

func stripLastSlash(dir string) string {
	if dir == "/" {
		return dir
	}
	if dir[len(dir)-1] == '/' {
		dir = dir[0 : len(dir)-1]
	}

	return dir
}

func resetRootPath(dir string) string {
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
	log.Log("\n\tSize: %d \tBlock size: %d \tBlocks: %d\n\tDevice: %d \tRdev: %d \tInode: %d \tLinks: %d\n\tUID: %d GID: %d\n\tAccess: %s\n\tModify: %s\n\tChange: %s\n\n",
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
