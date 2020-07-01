package main

import (
	"path"
	"strconv"
	"strings"
)

type Process struct {
	Id   uint
	Name string
}

type ProcessProvider interface {
	GetProcesses() ([]Process, error)
	GetProcessById(id uint) (Process, error)
}

type ProcfsProcessProvider struct {
	procfs Procfs
}

func (me ProcfsProcessProvider) GetProcesses() ([]Process, error) {
	fnames, err := me.procfs.Readdirnames("")
	if err != nil {
		return nil, err
	}
	r := make([]Process, len(fnames))
	n := 0
	for _, fn := range fnames {
		if id, err := strconv.ParseUint(fn, 10, 32); err == nil && id > 0 {
			id := uint(id)
			name, err := me.GetProcessName(id)
			if err != nil {
				return nil, err
			}
			r[n] = Process{Id: id, Name: name}
			n++
		}
	}

	result := make([]Process, 0)
	result = append(result, r[0:n]...)
	return result, nil
}

func (me ProcfsProcessProvider) GetProcessById(id uint) (Process, error) {
	name, err := me.GetProcessName(id)
	if err != nil {
		return Process{}, err
	}
	return Process{Id: id, Name: name}, nil
}

func (me ProcfsProcessProvider) GetProcessName(id uint) (string, error) {
	content, err := me.procfs.ReadFile(path.Join(strconv.Itoa(int(id)), "comm"))
	return strings.TrimSuffix(strings.ReplaceAll(string(content), "/", ""), "\n"), err
}
