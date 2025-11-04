package utils

import (
	"os"
	"path/filepath"
	"strconv"
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

// the first argument is an interface, to accept Taskstats Comm field
// of different architectures: uint8 on arm, int8 on the rest.
func IntSliceToString(aa interface{}, sep string) string {
	a := aa.([32]int8)
	if len(a) == 0 {
		return ""
	}

	b := make([]byte, len(a))
	for i, v := range a {
		if v == 0 {
			break
		}
		b[i] = byte(v)
	}
	return string(b)
}
