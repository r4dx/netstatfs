package main

import (
	"io/ioutil"
	"os"
	"path"
)

type Procfs interface {
	Readdirnames() ([]string, error)
	ReadFile(relativePath string) ([]byte, error)
}

type ProcfsImpl struct{}

const ProcBase = "/proc"

func (me ProcfsImpl) Readdirnames() ([]string, error) {
	procFile, err := os.Open(ProcBase)
	if err != nil {
		return nil, err
	}
	defer procFile.Close()
	return procFile.Readdirnames(0)
}

func (me ProcfsImpl) ReadFile(relativePath string) ([]byte, error) {
	return ioutil.ReadFile(path.Join(ProcBase, relativePath))
}
