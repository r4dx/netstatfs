package main

import (
	"regexp"
	"strconv"
)

type SocketProvider interface {
	GetSockets(processId uint) ([]ProcessSocket, error)
	GetProcessSocket(processId uint, socketId uint64) (ProcessSocket, error)
}

type procfsSocketProvider struct {
	procfs Procfs
	re     *regexp.Regexp
}

type ProcessSocket struct {
	Id        uint64
	INode     uint64
	ProcessId uint
}

func NewProcfsSocketProvider(procfs Procfs) SocketProvider {
	re := regexp.MustCompile(`^(socket:\[(?P<inode>\d*)\]|\[0000\]:(?P<inode>\d*))$`)
	return procfsSocketProvider{procfs, re}
}

func (me procfsSocketProvider) GetProcessSocket(processId uint, socketId uint64) (ProcessSocket, error) {
	file := strconv.FormatUint(uint64(processId), 10) + "/fd/" + strconv.FormatUint(socketId, 10)

	resolved, err := me.procfs.Readlink(file)
	if err != nil {
		return ProcessSocket{}, err
	}
	inode, err := me.getINodeIfSocket(resolved)
	if err != nil {
		return ProcessSocket{}, err
	}

	return ProcessSocket{INode: inode, ProcessId: processId, Id: socketId}, nil
}

func (me procfsSocketProvider) GetSockets(processId uint) ([]ProcessSocket, error) {
	base := strconv.Itoa(int(processId)) + "/fd/"

	files, err := me.procfs.Readdirnames(base)
	if err != nil {
		return nil, err
	}
	result := make([]ProcessSocket, 0)
	for _, file := range files {
		fd, err := strconv.ParseUint(file, 10, 64)
		if err != nil {
			continue
		}
		socket, err := me.GetProcessSocket(processId, fd)
		if err != nil {
			continue
		}
		result = append(result, socket)
	}

	return result, nil
}

func (me procfsSocketProvider) getINodeIfSocket(src string) (uint64, error) {
	matches := me.re.FindStringSubmatchIndex(src)
	outStr := string(me.re.ExpandString([]byte{}, "$inode", src, matches))
	res, err := strconv.ParseUint(outStr, 10, 64)
	if err != nil {
		return 0, err
	}
	return res, nil
}
