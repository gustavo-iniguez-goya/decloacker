package decloaker

import (
	"os"
	"syscall"
	"time"

	"github.com/gustavo-iniguez-goya/decloaker/pkg/log"
)

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

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

func PrintStat(paths []string) {
	stats := Stat(paths)

	for path, st := range stats {
		log.Info("Stat %s:\n", path)
		log.Detection("%s\t%d\t%s\t%s\n",
			st.Mode(),
			st.Size(),
			st.ModTime().Format(time.RFC3339),
			st.Name(),
		)
		if st == nil || st.Sys() == nil {
			log.Debug("stat.Sys() nil, not available\n")
			continue
		}
		PrintFileExtendedInfo(st.Sys())
	}
	log.Log("\n")
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
