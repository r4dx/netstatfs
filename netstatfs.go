package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

// import "github.com/google/gopacket/pcap"

func main() {
	mountpoint := flag.String("mount", "", "mountpoint for FS")
	flag.Parse()
	conn, err := fuse.Mount(*mountpoint, fuse.FSName("netstatfs"))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	netstatfs, err := NewNetstatfs()
	if err != nil {
		panic(err)
	}
	err = fs.Serve(conn, &netstatfs)
	if err != nil {
		panic(err)
	}
}

type Netstatfs struct {
	ProcessProvider ProcessProvider
	RootINode       uint64
}

func NewNetstatfs() (Netstatfs, error) {
	return Netstatfs{RootINode: 0,
		ProcessProvider: ProcfsProcessProvider{ProcfsImpl{}}}, nil
}

func (me Netstatfs) Root() (fs.Node, error) {
	return RootDir{Root: &me}, nil
}

type RootDir struct {
	Root *Netstatfs
}

func (me RootDir) Attr(ctx context.Context, attr *fuse.Attr) error {
	attr.Inode = (*me.Root).RootINode
	attr.Mode = os.ModeDir | 0o555 // dr-xr-xr-x
	return nil
}

func (me RootDir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	id, err := FileNameToProcessId(name)
	if err != nil {
		return nil, err
	}
	process, err := me.Root.ProcessProvider.GetProcessById(id)
	if err != nil {
		return nil, err
	}
	return ProcessDir{Root: me.Root,
		Process: process,
		INode:   uint64(process.Id)}, nil
}

func FileNameToProcessId(name string) (uint, error) {
	r := strings.Split(name, "_")
	if len(r) <= 1 {
		return 0, syscall.ENOENT
	}
	if id, err := strconv.Atoi(r[0]); err == nil && id > 0 {
		return uint(id), nil
	}
	return 0, syscall.ENOENT
}

func ProcessNameToFileName(id uint, name string) string {
	return fmt.Sprintf("%d_%s", id, name)
}

func (me RootDir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	processes, err := (*me.Root).ProcessProvider.GetProcesses()
	if err != nil {
		return nil, err
	}
	result := make([]fuse.Dirent, len(processes))
	for i, process := range processes {
		fn := ProcessNameToFileName(
			process.Id, process.Name)

		result[i] = fuse.Dirent{Inode: uint64(process.Id),
			Name: fn,
			Type: fuse.DT_Dir}
	}
	return result, nil
}

type ProcessDir struct {
	Root    *Netstatfs
	Process Process
	INode   uint64
}

func (me ProcessDir) Attr(ctx context.Context, attr *fuse.Attr) error {
	attr.Inode = me.INode
	attr.Mode = os.ModeDir | 0o555 // dr-xr-xr-x
	return nil
}

func (me ProcessDir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	return nil, syscall.ENOENT
}
