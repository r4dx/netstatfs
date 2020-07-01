package main

import (
	"path"
	"strconv"
)

type FileIdProvider interface {
	GetByProcessId(processId uint) (uint64, error)
	GetBySocketId(processId uint, socketId uint64) (uint64, error)
}

type ProcfsFileIdProvider struct {
	procfs Procfs
}

func (me ProcfsFileIdProvider) GetBySocketId(processId uint, socketId uint64) (uint64, error) {
	return me.procfs.GetInode(path.Join(strconv.FormatUint(uint64(processId), 10), "/fd/", strconv.FormatUint(socketId, 10)))
}

func (me ProcfsFileIdProvider) GetByProcessId(processId uint) (uint64, error) {
	return me.procfs.GetInode(strconv.FormatUint(uint64(processId), 10))
}
