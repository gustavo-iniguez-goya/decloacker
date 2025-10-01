package decloacker

// Exit codes
const (
	OK             = 0
	ERROR          = 1
	FILES_HIDDEN   = 50
	KMOD_HIDDEN    = 51
	CONTENT_HIDDEN = 52
	PID_BIND_MOUNT = 53
	PROC_HIDDEN    = 54
)

var (
	builtin_paths = map[string]string{
		"/etc/ld.so.preload":          "used to add userland rootkits",
		"/etc/ld.so.conf":             "",
		"/etc/passwd":                 "",
		"/etc/shadow":                 "",
		"/etc/motd":                   "",
		"/etc/update-motd.d/*":        "",
		"/etc/modules":                "",
		"/etc/modules-load.d/*":       "",
		"/etc/udev/rules.d/*":         "",
		"/etc/cron.d/*":               "",
		"/etc/crontab":                "",
		"/etc/xdg/autostart/*":        "",
		"/etc/rc.local":               "",
		"/etc/systemd/*":              "",
		"/usr/lib/modules-load.d/*":   "",
		"/var/spool/*":                "",
		"/home/*/.bashrc":             "",
		"/home/*/.config/autostart/*": "",
		"/tmp/*":                      "",
		"/lib/*":                      "",
		"/proc/net/*":                 "",
		"/proc/":                      "",
	}
)
