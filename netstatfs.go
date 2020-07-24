package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

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
	SocketProvider  SocketProvider
	FileIdProvider  FileIdProvider
	RootINode       uint64
}

func NewNetstatfs() (Netstatfs, error) {
	procfs := ProcfsImpl{}
	return Netstatfs{RootINode: 0,
		ProcessProvider: ProcfsProcessProvider{procfs},
		SocketProvider:  NewProcfsSocketProvider(procfs),
		FileIdProvider:  ProcfsFileIdProvider{procfs}}, nil
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
	id, err := fileNameToProcessId(name)
	if err != nil {
		return nil, err
	}
	process, err := me.Root.ProcessProvider.GetProcessById(id)
	if err != nil {
		return nil, err
	}
	inode, err := (*me.Root).FileIdProvider.GetByProcessId(id)
	if err != nil {
		return nil, err
	}
	return ProcessDir{Root: me.Root,
		Process: process,
		INode:   inode}, nil
}

func fileNameToProcessId(name string) (uint, error) {
	r := strings.Split(name, "_")
	if len(r) <= 1 {
		return 0, syscall.ENOENT
	}
	if id, err := strconv.ParseUint(r[0], 10, 32); err == nil && id > 0 {
		return uint(id), nil
	}
	return 0, syscall.ENOENT
}

func processNameToFileName(id uint, name string) string {
	return fmt.Sprintf("%d_%s", id, name)
}

func (me RootDir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	processes, err := (*me.Root).ProcessProvider.GetProcesses()
	if err != nil {
		return nil, err
	}
	result := make([]fuse.Dirent, len(processes))
	for i, process := range processes {
		fn := processNameToFileName(
			process.Id, process.Name)
		inode, err := (*me.Root).FileIdProvider.GetByProcessId(process.Id)
		if err != nil {
			return nil, err
		}

		result[i] = fuse.Dirent{Inode: inode,
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
	sockets, err := (*me.Root).SocketProvider.GetSockets(me.Process.Id)
	if err != nil {
		log.Printf("Couldn't get sockets for process=%d: %s\n", me.Process.Id, err)
		return nil, err
	}
	result := make([]fuse.Dirent, len(sockets))
	for i, socket := range sockets {
		inode, err := (*me.Root).FileIdProvider.GetBySocketId(me.Process.Id, socket.Id)
		if err != nil {
			log.Printf("Couldn't get fileid for process=%d, socket=%d: %s", me.Process.Id, socket.Id, err)
			return nil, err
		}
		result[i] = fuse.Dirent{Inode: inode,
			Name: socketToFileName(socket),
			Type: fuse.DT_File}
	}
	return result, nil
}

func fileNameToSocketId(name string) (uint64, error) {
	r := strings.Split(name, "_")
	if len(r) <= 1 {
		return 0, syscall.ENOENT
	}
	if id, err := strconv.ParseUint(r[0], 10, 64); err == nil {
		return id, nil
	}
	return 0, syscall.ENOENT
}

func socketToFileName(socket ProcessSocket) string {
	return socket.String() //fmt.Sprintf("%d_%s", socket.Id, "socket")
}

func (me ProcessDir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	id, err := fileNameToSocketId(name)
	if err != nil {
		return nil, err
	}
	socket, err := (*me.Root).SocketProvider.GetProcessSocket(me.Process.Id, id)
	if err != nil {
		log.Println("err: " + err.Error())
		return nil, err
	}
	return SocketFile{INode: socket.INode,
		Root:    me.Root,
		Process: me.Process,
		Socket:  socket}, nil
}

type SocketFile struct {
	INode   uint64
	Root    *Netstatfs
	Process Process
	Socket  ProcessSocket
	Sniffer Sniffer
}

func (me SocketFile) Attr(ctx context.Context, attr *fuse.Attr) error {
	attr.Inode = me.INode
	attr.Mode = 0o555
	attr.Size = 0
	return nil
}

func (me SocketFile) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	// 1. Need to handle open file event and create AF_PACKET socket at this point
	//    gopacket.Lazy, gopacket.NoCopy if gopacket
	//    Filter should include protocol={tcp,udp,icmp}{,6}, {local,remote}Port number, {local,remote}IP
	//    For unix domain sockets - https://github.com/mechpen/sockdump (kprobe for probe_unix_stream_sendmsg)
	// 1. NB Character device file is more applicable here but it doesn't seem like fuse library support /dev/cuse
	// 1. So let's emulate something resembling it - file size is zero but every Read request is processed
	//    In order to do it we need to put fuse lib into OpenDirectIO mode or else requests to empty files won't be handed to Read func
	//    NB tools like `tail -f` track file size so we still won't be able to use it
	//    We need to block each time there is no data - thus we also need to select on ctx.Done() in order to stop waiting when request is cancelled
	if req.Size <= 0 {
		req.Size = 512
	}
	select {
	// TODO: size is ignored now
	case resp.Data = <-me.Sniffer.Data(uint32(req.Size)):
		return nil
	case <-ctx.Done():
		return syscall.EINTR
	}
}

func (me SocketFile) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fs.Handle, error) {
	resp.Flags |= fuse.OpenDirectIO
	var err error
	me.Sniffer, err = NewSniffer(me.Socket.SocketInfo)
	if err != nil {
		log.Printf("Error openning " + err.Error() + "\n")
		return me, err
	}
	return me, nil
}

func (me SocketFile) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
	if me.Sniffer != nil {
		me.Sniffer.Close()
	}
	return nil
}
