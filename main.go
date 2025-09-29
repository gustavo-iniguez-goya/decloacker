package main

import (
	"fmt"
	"os"
	"time"

	"github.com/alecthomas/kong"
	"github.com/diskfs/go-diskfs"
	"github.com/gustavo-iniguez-goya/decloacker/pkg"
	disk "github.com/gustavo-iniguez-goya/decloacker/pkg/disk"
	dlog "github.com/gustavo-iniguez-goya/decloacker/pkg/log"
	"github.com/gustavo-iniguez-goya/decloacker/pkg/sys"
)

// CLI defines the full command structure.
var CLI struct {
	Format   string `short:"f" help:"" global:""`
	LogLevel string `help:"log level (debug,info,warn,error,detection). Use detection to display only detections" default:"info" enum:"debug,info,warning,error,detection"`
	//Output  string `short:"o" help:"" global:""`
	//LogDate bool   `global:""`
	//LogTime bool   `global:""`
	//LogUTC  bool   `global:""`

	// https://github.com/alecthomas/kong?tab=readme-ov-file#supported-tags
	// https://github.com/alecthomas/kong?tab=readme-ov-file#custom-named-decoders

	// TODO
	//Log struct {
	//	Format string `arg:"" optional:"" name:"format" help:"Output format: plain, text, json (default plain)." type:"format"`
	//	Output string `arg:"" optional:"" name:"output" help:"Output file (default stdout)." type:"file"`
	//} `cmd:"" help:"Logging options." hidden:""`

	Cp struct {
		Orig string `arg:"" optional:"" name:"orig" help:"Source path" type:"path"`
		Dest string `arg:"" optional:"" name:"dest" help:"Dest path" type:"path"`
	} `cmd:"" help:"Copy file via syscalls."`
	Rm struct {
		Paths []string `arg:"" required:"" name:"paths" help:"Paths to delete." type:"path"`
	} `cmd:"" help:"Delete files via syscalls."`
	Ls struct {
		Paths            []string `arg:"" optional:"" name:"paths" help:"Paths to list." type:"path"`
		Recursive        bool     `short:"r" help:"Enable deep scanning."`
		ShowExtendedInfo bool     `help:"show extended information"`
	} `cmd:"" help:"List files via syscalls."`
	Mv struct {
		Orig string `arg:"" optional:"" name:"orig" help:"Source path" type:"path"`
		Dest string `arg:"" optional:"" name:"dest" help:"Dest path" type:"path"`
	} `cmd:"" help:"Move files via syscalls."`
	Cat struct {
		Paths []string `arg:"" optional:"" name:"paths" help:"Paths to cat." type:"path"`
	} `cmd:"" help:"Cat files via syscalls."`
	Stat struct {
		Paths []string `arg:"" help:"File path to stat." required:"" name:"paths" type:"path"`
	} `cmd:"" help:"Get details of a file or directory"`
	Netstat struct {
		// FIXME: this enum affects other commands?
		// enum:"tcp,udp,udplite,icmp,dccp,sctp,igmp,raw"
		Protos []string `arg:"" sep:"," enum:"tcp,tcp6,udp,udp6,udplite,udplite6,icmp,icmp6,dccp,dccp6,sctp,sctp6,igmp,igmp6,raw,raw6,packet" optional:"" name:"protos" help:"Protocols to dump (tcp, udp, xdp, raw, packet, icmp, sctp, igmp, dccp) Add 6 for ipv6 protocols (tcp6, udp6, ...)."`
		//Family []string `arg:"" optional:"" name:"family" help:"Families to dump (AF_INET, AF_XDP, ...)."`
	} `cmd:"" help:"List connections from kernel via netlink."`
	Conntrack struct {
		List struct {
		} `cmd:"" help:"Dump conntrack connections table from kernel."`
	} `cmd:"" help:"Manipulate conntrack connections table."`

	Disk struct {
		Dev       string `short:"d" help:"Disk device to read (/dev/sda1, ...)" required:"" name:"dev"`
		Partition int    `short:"p" help:"Device partition to read (0, 1, 5, ...)" name:"partition"`
		Ls        struct {
			Paths     []string `arg:"" help:"Paths to read." required:"" name:"paths" type:"path"`
			Recursive bool     `short:"r" help:"Enable deep scanning."`
		} `cmd:"" help:"List directories and files by reading directly from the disk device"`
		Cp struct {
			Orig string `arg:"" help:"Origin file to copy." required:"" name:"orig" type:"path"`
			Dest string `arg:"" help:"Destination file." required:"" name:"dest" type:"path"`
		} `cmd:"" help:"Copy directories and files directly from the disk device"`
		// hidden, not implemented in go-disks yet.
		Mv struct {
			Orig string `arg:"" help:"Origin file to move or rename." required:"" name:"orig" type:"path"`
			Dest string `arg:"" help:"Destination file." required:"" name:"dest" type:"path"`
		} `cmd:"" help:"Rename files directly from the disk device" hidden:""`
		// hidden and dangerous, can cause filesystem errors
		Rm struct {
			Paths []string `arg:"" help:"Paths to delete. WARNING, DANGEROUS OPERATION, DO NOT USE" required:"" name:"paths" type:"path"`
		} `cmd:"" help:"Delete files directly from the disk device" hidden:""`
		Info struct {
			Paths []string `arg:"" help:"Paths to read." required:"" name:"paths" type:"path"`
		} `cmd:"" help:"Return information about a path"`
		Cat struct {
			Path string `arg:"" help:"File path to read." required:"" name:"path" type:"path"`
		} `cmd:"" help:"Reads the content of a file and prints it to stdout"`
	} `cmd:"" help:"Read files directly from the disk device."`

	Scan struct {
		HiddenFiles struct {
			Paths     []string `arg:"" help:"Paths to scan. Use /proc to analyze processes." required:"" name:"paths" type:"path"`
			Tool      string   `short:"t" optional:"" enum:"ls,find" default:"find" help:"System command to enumerate files and directories: ls, find."`
			Recursive bool     `short:"r" help:"Enable deep scanning."`
		} `cmd:"" help:"Look for hidden files, directories or processes (libc vs Go's std lib vs mmap)."`
		HiddenContent struct {
			Paths []string `arg:"" help:"Paths to scan." required:"" name:"paths" type:"path"`
		} `cmd:"" help:"Open a file and check if it has hidden content (libc vs Go's std lib vs mmap)."`
		HiddenLkms struct {
		} `cmd:"" help:"Look for hidden kernel modules."`
		HiddenProcs struct {
			BruteForce bool `short:"b" help:"Try to find processes via brute force."`
		} `cmd:"" help:"Look for hidden processes."`

		// TODO
		All struct {
			Paths     []string `arg:"" help:"Path to scan." required:"" name:"paths" type:"path"`
			Recursive bool     `short:"r" help:"Enable deep scanning."`
		} `cmd:"" help:"Scan a path." hidden:""`
	} `cmd:"" help:"Commands to decloack files, directories or kernel modules."`

	// TODO
	Config struct {
		Set struct {
			Key   string `arg:"" help:"Config key to set." required:""`
			Value string `arg:"" help:"Value to set." required:""`
		} `cmd:"" help:"Set a configuration value."`

		Get struct {
			Key string `arg:"" help:"Config key to get." required:""`
		} `cmd:"" help:"Get a configuration value."`
	} `cmd:"" help:"Configuration commands." hidden:""`
}

func main() {

	ctx := kong.Parse(&CLI,
		kong.Name("decloacker"),
		kong.Description("A generic malware unmasker"),
		kong.UsageOnError(),
	)
	dlog.NewLogger(CLI.Format)
	dlog.SetLogLevel(CLI.LogLevel)

	dlog.Log("decloacker v0.0, pid: %d\n\n", os.Getpid())
	var ldLib = os.Getenv("LD_LIBRARY_PRELOAD")
	if ldLib != "" {
		dlog.Detection("\tWARNING!!\nLD_LIBRARY_PRELOAD env var found: %s\n", ldLib)
		dlog.Separator()
	}

	var ret = decloacker.OK

	switch ctx.Command() {
	//case "log <format> <output>":
	//	fmt.Printf("log format: %s, file: %s\n", CLI.Log.Format, CLI.Log.Output)
	case "cp <orig> <dest>":
		ret = decloacker.Copy(CLI.Cp.Orig, CLI.Cp.Dest)
	case "rm <paths>":
		ret = decloacker.Delete(CLI.Rm.Paths)
	case "ls <paths>":
		printLs(CLI.Ls.ShowExtendedInfo)
	case "mv <orig> <dest>":
		ret = decloacker.Rename(CLI.Mv.Orig, CLI.Mv.Dest)
	case "cat <paths>":
		ret = decloacker.Cat(CLI.Cat.Paths)
	case "stat <paths>":
		printStat()

	case "netstat <protos>":
		ret = decloacker.Netstat(CLI.Netstat.Protos)
	case "netstat":
		ret = decloacker.Netstat([]string{"all"})

	case "conntrack list":
		decloacker.Conntrack()

	case "disk ls <paths>":
		orig, expected := decloacker.ListFiles(CLI.Disk.Ls.Paths[0], sys.CmdLs, CLI.Disk.Ls.Recursive)
		expected = disk.ReadDir(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Ls.Paths[0], diskfs.ReadOnly, CLI.Disk.Ls.Recursive)
		ret = decloacker.CompareFiles(orig, expected)
	case "disk cp <orig> <dest>":
		err := disk.Cp(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Cp.Orig, CLI.Disk.Cp.Dest, diskfs.ReadOnly)
		if err != nil {
			dlog.Error("%s\n", err)
			ret = decloacker.ERROR
		} else {
			dlog.Ok("OK\n")
		}
		// not implemented in go-diskfs
	case "disk mv <orig> <dest>":
		err := disk.Mv(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Cp.Orig, CLI.Disk.Cp.Dest, diskfs.ReadOnly)
		if err != nil {
			dlog.Error("%s\n", err)
			ret = decloacker.ERROR
		} else {
			dlog.Ok("OK\n")
		}
	case "disk info <paths>":
		list, err := disk.Info(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Info.Paths, diskfs.ReadWrite)
		if err != nil {
			ret = decloacker.ERROR
			dlog.Error("%s\n", err)
		} else {
			for _, file := range list {
				dlog.Log("%s\t%d\t%s\t%s\n", file.Mode(), file.Size(), file.ModTime().Format(time.RFC3339), file.Name())
			}
		}

	case "disk cat <path>":
		content, err := disk.ReadFile(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Cat.Path)
		if err != nil {
			dlog.Error("%s\n", err)
			ret = decloacker.ERROR
		} else {
			dlog.Info("cat %s:\n\n", CLI.Disk.Cat.Path)
			dlog.Detection("%s\n", content)
		}

	case "disk rm <paths>":
		err := disk.Rm(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Rm.Paths, diskfs.ReadWrite)
		if err != nil {
			dlog.Error("%s\n", err)
			ret = decloacker.ERROR
		}

	case "scan hidden-files <paths>":
		ret = decloacker.CheckHiddenFiles(CLI.Scan.HiddenFiles.Paths, CLI.Scan.HiddenFiles.Tool, CLI.Scan.HiddenFiles.Recursive)
	case "scan hidden-content <paths>":
		ret = decloacker.CheckHiddenContent(CLI.Scan.HiddenContent.Paths)
	case "scan hidden-lkms":
		ret = decloacker.CheckHiddenLKM()
	case "scan hidden-procs":
		ret = decloacker.CheckHiddenProcs(CLI.Scan.HiddenProcs.BruteForce)
	//case "scan all":
	//	checkAll(CLI.Scan.HiddenFiles.Paths, CLI.Scan.HiddenFiles.Recursive)

	/* TODO
	case "config set":
		runConfigSet(CLI.Config.Set.Key, CLI.Config.Set.Value)
	case "config get":
		runConfigGet(CLI.Config.Get.Key)
	*/
	default:
		fmt.Println("No command specified, showing help:", ctx.Command())
		ctx.PrintUsage(true)
		ret = decloacker.ERROR
	}
	os.Exit(ret)
}

func printLs(showExtendedInfo bool) {
	for _, p := range CLI.Ls.Paths {
		_, ls := decloacker.ListFiles(p, sys.CmdLs, CLI.Ls.Recursive)
		total := len(ls)
		for f, stat := range ls {
			dlog.Info("%v\t%d\t%s\t%s\n", stat.Mode(), stat.Size(), stat.ModTime().Format(time.RFC3339), f)
			if showExtendedInfo {
				decloacker.PrintFileExtendedInfo(stat.Sys())
			}
		}
		dlog.Log("\n")
		dlog.Info("%d files scanned\n\n", total)
	}
}

func printStat() {
	stats := decloacker.Stat(CLI.Stat.Paths)

	for path, st := range stats {
		dlog.Info("%s:\n", path)
		dlog.Info("%s\t%d\t%s\t%s\n",
			st.Mode(),
			st.Size(),
			st.ModTime().Format(time.RFC3339),
			st.Name(),
		)
		if st == nil || st.Sys() == nil {
			dlog.Debug("stat.Sys() nil, not available\n")
			continue
		}
		decloacker.PrintFileExtendedInfo(st.Sys())
	}
	dlog.Log("\n")
}

/*func checkAll(paths []string, deep bool) {
}

func runConfigSet(key, value string) {
	fmt.Printf("Setting config: %s = %s\n", key, value)
	// TODO: Save config to file or DB
}

func runConfigGet(key string) {
	fmt.Printf("Retrieving config for key: %s\n", key)
	// TODO: Load config from file or DB
	fmt.Println("Value: <mocked-value>")
}*/
