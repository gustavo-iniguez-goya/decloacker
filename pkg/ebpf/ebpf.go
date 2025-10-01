package ebpf

import (
	"bytes"
	_ "embed"
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
	hooks     = []link.Link{}
	LiveDir   = "/sys/fs/bpf/decloacker"
	TasksPath = "/sys/fs/bpf/decloacker/tasks"
	KmodsPath = "/sys/fs/bpf/decloacker/kmods"
	reTasks   = regexp.MustCompile(`pid=([0-9]+)\sppid=([0-9]+)`)
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
)

type Task struct {
	Comm string
	Pid  string
	PPid string
}

type Kmod struct {
	Addr  string
	AType string
	Func  string
	Name  string
	Type  string
}

func ConfigureIters() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Warn("[eBPF] unable to remove memlock")
	}

	for progName, code := range progList {
		log.Debug("Loading ebpf module %s\n", progName)

		collOpts := ebpf.CollectionOptions{}
		//specs, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(dumpTask[:]))
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
		os.Remove(progPaths[progName])
		err = os.Mkdir(LiveDir, 0600)
		if err := iter.Pin(progPaths[progName]); err != nil {
			log.Error("[eBPF] pinning tasks error: %s\n", err)
		}
		/*r, err := iter.Open()
		if err != nil {
			log.Error("iter.Open: %v\n", err)
		}*/
		hooks = append(hooks, iter)
	}

	log.Debug("[eBPF] loaded")
}

// GetPidList dumps the tasks that are active in the kernel.
// The list can be read in /sys/fs/bpf/decloacker/tasks
// since kernel 5.9
func GetPidList() (taskList []Task) {
	tasks, err := os.ReadFile(TasksPath)
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
		if len(parts) == 0 || len(parts[0]) < 3 {
			continue
		}
		taskList = append(taskList,
			[]Task{
				Task{Pid: parts[0][1], PPid: parts[0][2]},
			}...)
	}

	return taskList
}

// GetKmodList dumps the kernel modules that are active in the kernel.
// The list can be read in /sys/fs/bpf/decloacker/kmods
// since kernel 6.0
func GetKmodList() map[string]Kmod {
	kmodList := make(map[string]Kmod)

	kmods, err := os.ReadFile(KmodsPath)
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
		if strings.HasPrefix(parts[0][4], "__builtin") {
			continue
		}
		kmodList[parts[0][4]] = Kmod{
			Addr:  parts[0][1],
			AType: parts[0][2],
			Func:  parts[0][3],
			Name:  parts[0][4],
			Type:  parts[0][5],
		}
	}

	return kmodList
}

func CleanupIters() {
	log.Debug("ebpf.CleanupIters()\n")
	for _, h := range hooks {
		h.Close()
	}

	os.Remove(TasksPath)
	os.Remove(KmodsPath)
}
