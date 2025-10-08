/*   Copyright (C) 2025 Gustavo Iñiguez Goya
//
//   This file is part of decloacker.
//
//   decloacker is free software: you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation, either version 3 of the License, or
//   (at your option) any later version.
//
//   decloacker is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with decloacker.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/alecthomas/kong"
	"github.com/diskfs/go-diskfs"
	"github.com/gustavo-iniguez-goya/decloacker/pkg"
	disk "github.com/gustavo-iniguez-goya/decloacker/pkg/disk"
	"github.com/gustavo-iniguez-goya/decloacker/pkg/ebpf"
	dlog "github.com/gustavo-iniguez-goya/decloacker/pkg/log"
	"github.com/gustavo-iniguez-goya/decloacker/pkg/sys"
)

func main() {
	ctx := kong.Parse(&CLI,
		kong.Name("decloacker"),
		kong.Description("A generic malware unmasker"),
		kong.UsageOnError(),
	)

	dlog.NewLogger(CLI.Format)
	dlog.SetLogLevel(CLI.LogLevel)

	var ldLib = os.Getenv("LD_LIBRARY_PRELOAD")
	if ldLib != "" {
		dlog.Detection("\tWARNING!!\nLD_LIBRARY_PRELOAD env var found: %s\n", ldLib)
		dlog.Separator()
	}

	ebpf.ConfigureIters(CLI.PinKernelLists)

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
		decloacker.PrintStat(CLI.Stat.Paths)

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
				dlog.Detection("%s\t%d\t%s\t%s\n", file.Mode(), file.Size(), file.ModTime().Format(time.RFC3339), file.Name())
			}
		}

	case "disk cat <path>":
		content, err := disk.ReadFile(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Cat.Path)
		if err != nil {
			dlog.Error("%s\n", err)
			ret = decloacker.ERROR
		} else {
			dlog.Ok("cat %s:\n\n", CLI.Disk.Cat.Path)
			dlog.Detection("%s", content)
			dlog.Log("\n")
		}

	case "disk rm <paths>":
		err := disk.Rm(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Rm.Paths, diskfs.ReadWrite)
		if err != nil {
			dlog.Error("%s\n", err)
			ret = decloacker.ERROR
		} else {
			dlog.Ok("rm %v\n\n", CLI.Disk.Rm.Paths)
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

	case "dump files":
		dlog.Detection("%-10s%-10s%-6s%-8s%-5s%-5s %-16s %s\t%s\n",
			"Pid", "PPid", "Fd", "Inode", "UID", "GID", "File", "Comm", "Exe")
		files := ebpf.GetFileList()
		for _, f := range files {
			dlog.Detection("%-10s%-10s%-6s%-8s%-5s%-5s %-16s %s\t%s\n",
				f.Pid, f.PPid,
				f.Fd, f.Inode,
				f.Uid, f.Gid,
				f.Comm, f.File, f.Exe,
			)
		}
	case "dump kmods":
		dlog.Detection("%-20s\t%-10s\t%s\t%s\t%s\n",
			"Name", "Type", "Symbol", "Address", "Function")
		kmods := ebpf.GetKmodList()
		for _, k := range kmods {
			dlog.Detection("%-20s\t%-10s\t%s\t%s\t%s\n",
				k.Name,
				k.Type,
				k.AType,
				k.Addr,
				k.Func,
			)
		}
	case "dump tasks":
		dlog.Detection("%-10s%-10s%-8s%-5s%-5s %-16s %s\n",
			"Pid", "PPid", "Inode", "UID", "GID", "Comm", "Exe")
		tasks := ebpf.GetPidList()
		for _, t := range tasks {
			dlog.Detection("%-10s%-10s%-8s%-5s%-5s %-16s %s\n",
				t.Pid, t.PPid,
				t.Inode,
				t.Uid, t.Gid,
				t.Comm, t.Exe,
			)
		}

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

	ebpf.CleanupIters()
	os.Exit(ret)
}

func printLs(showExtendedInfo bool) {
	for _, p := range CLI.Ls.Paths {
		_, ls := decloacker.ListFiles(p, sys.CmdLs, CLI.Ls.Recursive)
		total := len(ls)
		for f, stat := range ls {
			if stat == nil {
				dlog.Info("%s (no stat info)\n", f)
				continue
			}
			dlog.Detection("%v\t%d\t%s\t%s\n", stat.Mode(), stat.Size(), stat.ModTime().Format(time.RFC3339), f)
			if showExtendedInfo {
				decloacker.PrintFileExtendedInfo(stat.Sys())
			}
		}
		dlog.Log("\n")
		dlog.Info("%d files scanned\n\n", total)
	}
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
