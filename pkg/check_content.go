package decloacker

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/gustavo-iniguez-goya/decloacker/pkg/log"
	sys "github.com/gustavo-iniguez-goya/decloacker/pkg/sys"
)

// XXX: a file may have changed when reading it with cat and later with syscalls.
func CheckHiddenContent(paths []string) int {
	//Info("checking hidden files under %v\n", paths)
	ret := OK

	for _, f := range paths {
		hiddenFound := false
		log.Info("Checking for hidden content %s\n", f)
		catFiles := sys.Cat("cat", f)

		stat, err := os.Stat(f)
		if err != nil {
			log.Error("Unable to stat %s\n", err)
			continue
		}
		if stat.IsDir() {
			continue
		}
		// XXX: skip big files?

		raw, err := ioutil.ReadFile(f)
		fileSize := int64(len(raw))
		content := string(raw)
		if err != nil {
			log.Warn("%s cannot be read\n", f)
		} else {
			// XXX: sizes may differ if the file is a symbolic link to /proc, like /etc/mtab
			if !strings.HasPrefix(f, "/proc") && fileSize != stat.Size() {
				log.Detection("\n=== CONTENT WARNING (read) %s ===\n", f)
				log.Detection("size differs (content: %d, stat.size: %d, symlink: %v), %s\n", fileSize, stat.Size(), stat.Mode(), f)
				log.Detection("====================================\n")
				ret = CONTENT_HIDDEN
			}
			if content != catFiles[f] {
				hiddenFound = true

				ret = FILES_HIDDEN
				log.Detection("\n=== CONTENT WARNING (read) %s ===\n", f)
				log.Detection("cat content:\n %v\n", catFiles[f])
				log.Detection("-----------------------------------------------------------------\n")
				log.Detection("Go read content:\n %s\n", content)
				log.Detection("====================================\n")

				ret = CONTENT_HIDDEN
			}
		}

		// don't mmap /proc or /dev/shm
		if strings.HasPrefix(f, "/proc") || strings.HasPrefix(f, "/dev/shm") {
			continue
		}
		mSize, mData, err := MmapFile(f)
		if err != nil {
			log.Warn("mmap: %s\n", err)
			continue
		}

		// if we haven't found anything, try it with mmap
		if !hiddenFound {
			if mSize != fileSize {
				log.Detection("\n=== CONTENT WARNING (mmap) %s ===\n", f)
				log.Detection("size differs (content: %d, mmap.size: %d, %s)\n", fileSize, mSize, f)
				log.Log("====================================\n")
				ret = CONTENT_HIDDEN
			}

			if mData != catFiles[f] {
				ret = FILES_HIDDEN
				log.Detection("\n=== CONTENT WARNING (mmap) %s ===\n", f)
				log.Detection("cat content:\n %v\n", catFiles[f])
				log.Detection("-----------------------------------------------------------------\n")
				log.Detection("Go mmap content:\n %s\n", content)
				log.Detection("====================================\n")
				ret = CONTENT_HIDDEN
			}
		}
	}

	if ret == OK {
		log.Info("no hidden content found\n\n")
	}

	return ret
}
