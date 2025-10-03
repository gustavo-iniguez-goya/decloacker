package ebpf

import (
	"bytes"
	_ "embed"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gustavo-iniguez-goya/decloacker/pkg/log"
)

//go:embed kern/dump_tasks.o
// this line must go here
var dumpTask []byte

//go:embed kern/dump_kmods.o
var dumpKmod []byte

var (
	LiveDir   = "/sys/fs/bpf/decloacker"
	TasksPath = "/sys/fs/bpf/decloacker/tasks"
	KmodsPath = "/sys/fs/bpf/decloacker/kmods"
	reTasks   = regexp.MustCompile(`pid=([0-9]+)\sppid=([0-9]+)\sinode=([0-9]+)\suid=([0-9]+)\sgid=([0-9]+)\scomm=(.{0,16})exe=(.*)$`)
	// addr=0xffffffffc4668010 atype=T func=hide_proc_modules_init name=lab_hide type=FTRACE_MOD 0x8000
	reKmods       = regexp.MustCompile(`addr=([a-zA-Z0-9]+)\satype=([a-zA-Z0-9])\sfunc=([a-zA-Z0-9\-_]+)\sname=([a-zA-Z0-9\-_]+)\stype=([a-zA-Z0-9\-_]+)`)
	ProgDumpTasks = "dump_tasks"
	ProgDumpKmods = "dump_kmods"

	progList = map[string][]byte{
		ProgDumpTasks: dumpTask,
		ProgDumpKmods: dumpKmod,
	}
	progPaths = map[string]string{
		ProgDumpTasks: TasksPath,
		ProgDumpKmods: KmodsPath,
	}
	progHooks = map[string]*link.Iter{}
)

type Task struct {
	Exe   string
	Comm  string
	Inode string
	Uid   string
	Gid   string
	Pid   string
	PPid  string
}

type Kmod struct {
	Addr  string
	AType string
	Func  string
	Name  string
	Type  string
}

func ConfigureIters(pinIters bool) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Warn("[eBPF] unable to remove memlock")
	}

	for progName, code := range progList {
		log.Debug("Loading ebpf module %s\n", progName)

		collOpts := ebpf.CollectionOptions{}
		specs, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(code[:]))
		if err != nil {
			log.Error("[eBPF] module specs error %s: %s\n", progName, err)
			continue
		}
		iterTask, err := ebpf.NewCollectionWithOptions(specs, collOpts)
		if iterTask == nil {
			log.Error("[eBPF] iter task: %s\n", err)
			continue
		}
		prog := iterTask.Programs[progName]
		if prog == nil {
			log.Error("[eBPF] iter task nil %s: %s\n", progName, err)
			return
		}

		iter, err := link.AttachIter(link.IterOptions{
			Program: prog,
		})
		if err != nil {
			log.Error("[eBPF] iter link attach error %s: %s\n", progName, err)
			return
		}

		if pinIters {
			os.Remove(progPaths[progName])
			err = os.Mkdir(LiveDir, 0600)
			if err := iter.Pin(progPaths[progName]); err != nil {
				log.Error("[eBPF] pinning tasks error: %s\n", err)
			}
		}
		progHooks[progName] = iter
	}

	log.Debug("[eBPF] loaded")
}

// GetPidList dumps the tasks that are active in the kernel.
// The list can be read in /sys/fs/bpf/decloacker/tasks
// since kernel 5.9
func GetPidList() (taskList []Task) {
	iter, found := progHooks[ProgDumpTasks]
	if !found {
		log.Debug("iter %s not configured?\n", ProgDumpTasks)
		return taskList
	}
	iterReader, err := iter.Open()
	if err != nil {
		log.Error("iter.Open: %v\n", err)
		return taskList
	}
	defer iterReader.Close()

	tasks, err := io.ReadAll(iterReader)
	if err != nil {
		log.Error("%s not available\n", TasksPath)
		return taskList
	}
	if len(tasks) == 0 {
		log.Warn("[eBPF] kernel tasks empty (check previous errors).\n")
		return taskList
	}
	lines := strings.Split(string(tasks), "\n")
	for _, line := range lines {
		parts := reTasks.FindAllStringSubmatch(line, 1)
		if len(parts) == 0 || len(parts[0]) < 4 {
			continue
		}
		pid := parts[0][1]
		ppid := parts[0][2]
		// exclude threads
		if pid != ppid {
			continue
		}
		inode := parts[0][3]
		uid := parts[0][4]
		gid := parts[0][5]
		comm := parts[0][6]
		exe := parts[0][7]
		// index 0 is the string that matched
		taskList = append(taskList,
			[]Task{
				Task{
					Pid:   pid,
					PPid:  ppid,
					Inode: inode,
					Uid:   uid,
					Gid:   gid,
					Comm:  comm,
					Exe:   exe,
				},
			}...)
	}

	return taskList
}

// GetKmodList dumps the kernel modules that are active in the kernel.
// The list can be read in /sys/fs/bpf/decloacker/kmods
// since kernel 6.0
func GetKmodList() map[string]Kmod {
	kmodList := make(map[string]Kmod)

	iter, found := progHooks[ProgDumpKmods]
	if !found {
		log.Debug("iter %s not configured?\n", ProgDumpKmods)
		return kmodList
	}
	iterReader, err := iter.Open()
	if err != nil {
		log.Error("iter.Open: %v\n", err)
		return kmodList
	}
	defer iterReader.Close()

	kmods, err := io.ReadAll(iterReader)
	if err != nil {
		log.Error("%s not available\n", KmodsPath)
		return kmodList
	}

	if len(kmods) == 0 {
		log.Warn("[eBPF] kernel tasks empty (check previous errors).\n")
		return kmodList
	}
	lines := strings.Split(string(kmods), "\n")
	for _, line := range lines {
		parts := reKmods.FindAllStringSubmatch(line, 1)
		if len(parts) == 0 || len(parts[0]) < 5 {
			continue
		}
		atype := parts[0][2]
		kname := parts[0][4]
		if strings.HasPrefix(kname, "__builtin") && atype == "t" {
			log.Debug("excluding kmod %s:\n\t%v\n", kname, line)
			continue
		}
		// index 0 is the string that matched
		kmodList[parts[0][4]] = Kmod{
			Addr:  parts[0][1],
			AType: atype,
			Func:  parts[0][3],
			Name:  kname,
			Type:  parts[0][5],
		}
	}

	return kmodList
}

func CleanupIters() {
	for _, h := range progHooks {
		h.Close()
	}

	//os.Remove(TasksPath)
	//os.Remove(KmodsPath)
}
