package main

import (
	"context"
	"flag"
	"net"
	"os"
	"syscall"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

// import "github.com/google/gopacket/pcap"

func main() {
	var mountpoint = flag.String("mount", "", "mountpoint for FS")
	flag.Parse()
	var conn, err = fuse.Mount(*mountpoint, fuse.FSName("netstatfs"))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	err = fs.Serve(conn, FS{1})
	if err != nil {
		panic(err)
	}
}

type FS struct {
	RootINode uint64
}

type NI struct {
	Ni    net.Interface
	Inode uint64
}

func (me FS) Root() (fs.Node, error) {
	nis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	nameToNI := make(map[string]NI)
	for i, ni := range nis {
		nameToNI[ni.Name] = NI{Ni: ni, Inode: uint64(i) + me.RootINode + 1}
	}

	return NIDir{nis: &nis, nameToNI: &nameToNI, RootINode: me.RootINode}, nil
}

type NIDir struct {
	RootINode uint64
	nis       *[]net.Interface
	nameToNI  *map[string]NI
}

func (me NIDir) Attr(ctx context.Context, attr *fuse.Attr) error {
	attr.Inode = me.RootINode
	attr.Mode = os.ModeDir | 0o555 // dr-xr-xr-x
	return nil
}

func (me NIDir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	ni := (*me.nameToNI)[name]
	return NIFile{Inode: ni.Inode}, nil
}

func (me NIDir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	result := make([]fuse.Dirent, len(*me.nis))
	for i, iface := range *me.nis {
		result[i] = fuse.Dirent{Inode: uint64(i), Name: iface.Name, Type: fuse.DT_File}
	}
	return result, nil
}

type NIFile struct {
	Inode uint64
}

func (me NIFile) Attr(ctx context.Context, attr *fuse.Attr) error {
	attr.Inode = me.Inode
	attr.Mode = 0o444 //r--r--r--
	attr.Size = 0
	return nil
}

func (NIFile) ReadAll(ctx context.Context) ([]byte, error) {
	return nil, syscall.ENOENT
}
