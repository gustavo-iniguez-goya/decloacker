package decloacker

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
