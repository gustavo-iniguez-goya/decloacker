package decloacker

import (
	"io/fs"
	"os"
	"time"

	"github.com/gustavo-iniguez-goya/decloacker/pkg/decloacker/log"
)

// CompareFiles checks if 2 directories have the same number of files
func CompareFiles(orig, expected map[string]os.FileInfo) int {
	hidden := make(map[string]fs.FileInfo)

	for file, stat := range expected {
		if stat != nil {
			log.Log("%s\t%d\t%s\t%s\n",
				stat.Mode(),
				stat.Size(),
				stat.ModTime().Format(time.RFC3339),
				file)
		}

		if statOrig, found := orig[file]; !found {
			hidden[file] = stat
			log.Warn("\tHIDDEN: %s\n\n", file)
			continue
		} else {
			if statOrig != nil && stat != nil {
				if statOrig.Size() != stat.Size() {
					log.Detection("\tWARNING, size differs for %s, expected: %d, %d\n", file, stat.Size(), statOrig.Size())
				}
			}
		}
	}

	// we should not have more files than what ls returns.
	// when scanning /proc, there can be transitional pids though.
	if len(orig) > len(expected) {
		for file, statSrc := range orig {
			if _, found := expected[file]; !found {
				if statSrc != nil {
					log.Debug("??? %s\t%d\t%s\t%s\n",
						statSrc.Mode(),
						statSrc.Size(),
						statSrc.ModTime().Format(time.RFC3339),
						file)
					continue
				}
			}
		}
	}

	ret := OK

	if len(hidden) > 0 {
		ret = FILES_HIDDEN

		log.Detection("\nHIDDEN dirs/files found:\n\n")
		for h, stat := range hidden {
			if stat != nil {
				log.Detection("\t%v\t%d\t%s\t%s\n", stat.Mode(), stat.Size(), stat.ModTime().Format(time.RFC3339), h)
				continue
			}
			log.Debug("\t(stat not available) %s\n", h)
		}
		log.Log("\n")
		log.Info("use \"%s\" to backup the files, or \"%s\" to delete them", "decloacker disk cp <orig> <dest>", "decloacker disk rm <path>")
		log.Log("\n\n")
	} else {
		log.Log("\n")
		log.Info("\tfiles checked (%d/%d)\n", len(orig), len(expected))
		log.Info("\tno hidden dirs/files found\n\n")
	}

	return ret
}

// CheckHiddenFiles checks differences between the ls output and the output of
// Go's standard lib.
func CheckHiddenFiles(paths []string, tool string, deep bool) int {
	ret := OK
	log.Info("Checking hidden files with \"%s\" %q\n\n", tool, paths)

	for _, p := range paths {
		orig, expected := ListFiles(p, tool, deep)
		r := CompareFiles(orig, expected)

		if r != OK {
			ret = r
		}
	}

	return ret
}
