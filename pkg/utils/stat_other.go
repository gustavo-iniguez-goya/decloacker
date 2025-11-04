//go:build linux && (amd64 || arm64 || 386)

package utils

import (
	"syscall"
	"time"

	"github.com/gustavo-iniguez-goya/decloaker/pkg/log"
)

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
		time.Unix(int64(statt.Atim.Sec), int64(statt.Atim.Nsec)),
		time.Unix(int64(statt.Mtim.Sec), int64(statt.Mtim.Nsec)),
		time.Unix(int64(statt.Ctim.Sec), int64(statt.Ctim.Nsec)),
	)
}
