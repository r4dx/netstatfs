package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
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
	err = fs.Serve(conn, NewFS())
	if err != nil {
		panic(err)
	}
}

type FS struct {
	RootINode uint64
	LastINode uint64
	fnToId    *map[string]uint64
}

func NewFS() *FS {
	fnToId := make(map[string]uint64, 0)
	return &FS{1, 1, &fnToId}
}

func (me FS) Register(fn string) (uint64, error) {
	log.Printf("FS.Register - adding " + fn)
	if id, exists := (*me.fnToId)[fn]; exists {
		log.Fatal("FS.Register - file exists " + fn)
		return id, syscall.EEXIST
	}
	me.LastINode++
	(*me.fnToId)[fn] = me.LastINode
	return me.LastINode, nil
}

type ProcessEntry struct {
	Filename string
	Process  Process
	INode    uint64
}

func (me FS) Root() (fs.Node, error) {
	processes, err := GetProcesses()
	if err != nil {
		return nil, err
	}
	filenameToPE := make(map[string]ProcessEntry)
	for _, pe := range processes {
		fn := fmt.Sprintf("%d_%s", pe.Id, pe.Name)
		id, err := me.Register("/" + fn)
		if err != nil {
			return nil, err
		}
		filenameToPE[fn] = ProcessEntry{Filename: fn, Process: pe, INode: id}
	}

	return RootDir{FilenameToPE: &filenameToPE, Root: &me}, nil
}

type RootDir struct {
	Root         *FS
	FilenameToPE *map[string]ProcessEntry
}

func (me RootDir) Attr(ctx context.Context, attr *fuse.Attr) error {
	attr.Inode = (*me.Root).RootINode
	attr.Mode = os.ModeDir | 0o555 // dr-xr-xr-x
	return nil
}

func (me RootDir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	pe := (*me.FilenameToPE)[name]
	return ProcessDir{Root: me.Root, ProcessEntry: pe, INode: pe.INode}, nil
}

func (me RootDir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	result := make([]fuse.Dirent, len(*me.FilenameToPE))
	i := 0
	for _, pe := range *me.FilenameToPE {
		result[i] = fuse.Dirent{Inode: pe.INode, Name: pe.Filename, Type: fuse.DT_Dir}
		i++
	}
	return result, nil
}

type ProcessDir struct {
	Root         *FS
	ProcessEntry ProcessEntry
	INode        uint64
}

func (me ProcessDir) Attr(ctx context.Context, attr *fuse.Attr) error {
	attr.Inode = (*me.Root).RootINode
	attr.Mode = os.ModeDir | 0o555 // dr-xr-xr-x
	return nil
}

func (me ProcessDir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	return nil, syscall.ENOENT
}
