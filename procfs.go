package main

import (
	"errors"
	"io/ioutil"
	"os"
	"path"
	"syscall"
)

type Procfs interface {
	Readdirnames(relativePath string) ([]string, error)
	ReadFile(relativePath string) ([]byte, error)
	Readlink(relativePath string) (string, error)
	GetInode(relativePath string) (uint64, error)
}

type ProcfsImpl struct{}

const ProcBase = "/proc"

func (me ProcfsImpl) Readdirnames(relativePath string) ([]string, error) {
	procFile, err := os.Open(path.Join(ProcBase, relativePath))
	if err != nil {
		return nil, err
	}
	defer procFile.Close()
	return procFile.Readdirnames(0)
}

func (me ProcfsImpl) ReadFile(relativePath string) ([]byte, error) {
	return ioutil.ReadFile(path.Join(ProcBase, relativePath))
}

func (me ProcfsImpl) Readlink(relativePath string) (string, error) {
	return os.Readlink(path.Join(ProcBase, relativePath))
}

func (me ProcfsImpl) GetInode(relativePath string) (uint64, error) {
	fi, err := os.Stat(path.Join(ProcBase, relativePath))
	if err != nil {
		return 0, err
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("Cannot convert Stat result to Stat_t")
	}
	return stat.Ino, nil
}
