package decloaker

import (
	"bytes"
	"io/fs"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"

	"github.com/gustavo-iniguez-goya/decloaker/pkg/ebpf"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/log"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/utils"
)

type taintT struct {
	letter string
	reason string
}

var (
	taint_values = map[int]taintT{
		0:  {"G/P", "proprietary module was loaded (G means all modules GPL; P means a proprietary module exists)"},
		1:  {"F", "module was force loaded (insmod -f)"},
		2:  {"S", "kernel running on an out-of-spec system / unsupported SMP/hardware configuration"},
		3:  {"R", "module was force unloaded (rmmod -f)"},
		4:  {"M", "processor reported a Machine Check Exception (MCE)"},
		5:  {"B", "bad page referenced / unexpected page flags (possible hardware or kernel bug)"},
		6:  {"U", "taint requested by userspace"},
		7:  {"D", "kernel has died recently (there was an OOPS or BUG)"},
		8:  {"A", "ACPI table overridden by user"},
		9:  {"W", "kernel issued warning"},
		10: {"C", "staging driver was loaded"},
		11: {"I", "workaround for bug in platform firmware applied"},
		12: {"O", "externally-built ('out-of-tree') module was loaded"},
		13: {"E", "unsigned module loaded on a kernel that supports module signatures"},
		14: {"L", "soft lockup occurred"},
		15: {"K", "kernel has been live patched"},
		16: {"X", "auxiliary taint, distro-defined"},
		17: {"T", "kernel built with randstruct plugin (set at build time)"},
		18: {"N", "an in-kernel test (e.g. KUnit) has been run"},
		19: {"J", "userspace used mutating debug op in fwctl (fwctl debug write)"},
	}

	// search for kmods under /sys/kernel/tracing/*
	reKmodBrckt = regexp.MustCompile(`\[([a-zA-Z0-9_-]+)\]`)
)

func CheckHiddenLKM() int {
	tainted := CheckTainted()
	retT := CheckTracingModules()
	retP := CheckProcModules(tainted)

	if retT != OK || retP != OK {
		return retT
	}
	log.Ok("no kernel modules hidden found\n")

	return OK
}

func CheckTainted() bool {
	log.Info("Checking kernel integrity\n")

	tainted := false
	val, _ := os.ReadFile("/proc/sys/kernel/tainted")
	value, _ := strconv.Atoi(string(bytes.Trim(val, "\n")))
	if value == 0 {
		log.Ok("kernel not tainted\n")
		return tainted
	}

	log.Detection("WARNING: kernel tainted\n")
	for bit, t := range taint_values {
		mask := 1 << bit
		if value&mask != 0 {
			tainted = true
			log.Log("\t(%s) %s\n", t.letter, t.reason)
		}
	}
	log.Log("\n")

	return tainted
}

// CheckProcModules verifies that all tainted modules exists in /proc/modules and /proc/kallsyms.
func CheckProcModules(tainted bool) int {
	log.Info("Checking loaded kernel modules\n")

	tainted_kmods := false
	ret := OK
	kmodList := make(map[string]fs.DirEntry)
	procModules, _ := ioutil.ReadFile("/proc/modules")
	procKallsyms, _ := ioutil.ReadFile("/proc/kallsyms")
	ksymList := ebpf.GetKmodList()

	kmods, _ := os.ReadDir("/sys/module")
	for _, k := range kmods {
		rktPath := "/sys/module/" + k.Name() + "/taint"
		log.Debug("checking kmod %s\n", rktPath)

		tainted, _ := os.ReadFile(rktPath)
		tainted = bytes.Trim(tainted, " \t\n")
		taintFlags := bytes.Trim(tainted, " \t\n")
		if !bytes.Equal(taintFlags, []byte("")) {
			tainted_kmods = true
			log.Detection("tainted: %s, %s\n", k, tainted)
			kmodList[k.Name()] = k
			if !bytes.Contains(procModules, []byte(k.Name())) {
				log.Detection("\n\tWARNING: \"%s\" kmod HIDDEN from /proc/modules\n\n", k.Name())
				ret = KMOD_HIDDEN
			}
			if !bytes.Contains(procKallsyms, []byte(k.Name())) {
				log.Detection("\n\tWARNING: \"%s\" kmod HIDDEN from /proc/kallsyms\n\n", k.Name())
				ret = KMOD_HIDDEN
			}
		}
	}
	for kname, kmod := range ksymList {
		if kmod.Type != "MOD" && kmod.Type != "FTRACE_MOD" {
			continue
		}
		if !utils.Exists("/sys/module/" + kname) {
			log.Detection("\n\tWARNING (eBPF): \"%s\" kmod HIDDEN from /sys/module\n", kname)
			log.Log("\t%q\n", kmod)
			ret = KMOD_HIDDEN
		}
		if !bytes.Contains(procModules, []byte(kname)) {
			log.Detection("\n\tWARNING (eBPF): \"%s\" kmod HIDDEN from /proc/modules\n", kname)
			log.Log("\t%q\n", kmod)
			ret = KMOD_HIDDEN
		}
		if !bytes.Contains(procKallsyms, []byte(kname)) {
			log.Detection("\n\tWARNING (eBPF): \"%s\" kmod HIDDEN from /proc/kallsyms\n", kname)
			log.Log("\t%q\n", kmod)
			ret = KMOD_HIDDEN
		}
	}
	if ret != OK {
		log.Log("\n")
	}

	if tainted && !tainted_kmods {
		log.Detection("\n\tWARNING: the kernel is tainted, but we haven't found any kmod tainting the kernel. REVIEW\n\n")
	}

	return ret
}

// CheckTracingModules verifies that all modules hooking functions exists under /sys/modules/, /proc/modules and /proc/kallsyms.
func CheckTracingModules() int {
	log.Info("Checking kernel modules hooks\n")

	ret := OK
	procModules, _ := ioutil.ReadFile("/proc/modules")
	procKallsyms, _ := ioutil.ReadFile("/proc/kallsyms")
	kmodList := make(map[string]struct{})

	monitorPaths := []string{
		"/sys/kernel/tracing/enabled_functions",
		"/sys/kernel/tracing/touched_functions",
	}

	for _, path := range monitorPaths {
		if !utils.Exists(path) {
			continue
		}
		log.Debug(" scanning %s\n", path)
		content, err := os.ReadFile(path)
		if err != nil {
			log.Error(" error reading %s: %s\n", path, err)
			continue
		}
		kmods := reKmodBrckt.FindAllStringSubmatch(string(content), -1)
		if len(kmods) == 0 {
			log.Debug(" no kmods found hooking functions in %s\n", path)
			continue
		}

		for _, k := range kmods {
			if _, found := kmodList[k[1]]; found {
				continue
			}
			log.Debug(" analyzing kmod: %s\n", k[1])

			log.Debug(" checking %s in /proc/modules\n")
			if !bytes.Contains(procModules, []byte(k[1])) {
				log.Detection("\tWARNING (tracing): possible kmod hidden from /proc/modules: %v\n", k[1])
				kmodList[k[1]] = struct{}{}
			}
			log.Debug(" checking /proc/kallsyms\n")
			if !bytes.Contains(procKallsyms, []byte(k[1])) {
				log.Detection("\tWARNING (tracing): possible kmod hidden from /proc/kallsyms: %v\n", k[1])
				kmodList[k[1]] = struct{}{}
			}
			log.Debug(" checking /sys/module/%s\n", k[1])
			if !utils.Exists("/sys/module/" + k[1]) {
				log.Detection("\tWARNING (tracing): possible kmod hidden from /sys/module: %v\n", k[1])
				kmodList[k[1]] = struct{}{}
			}
		}
	}
	if len(kmodList) > 0 {
		log.Log("\n")
		ret = KMOD_HIDDEN
	}

	return ret
}
