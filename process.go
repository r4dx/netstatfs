package main

import (
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
)

type Process struct {
	Id   uint
	Name string
}

const ProcBase = "/proc"

func GetProcesses() ([]Process, error) {
	procf, err := os.Open(ProcBase)
	if err != nil {
		return nil, err
	}
	defer procf.Close()
	fnames, err := procf.Readdirnames(0)
	if err != nil {
		return nil, err
	}
	r := make([]Process, len(fnames))
	n := 0
	for _, fn := range fnames {
		if id, err := strconv.Atoi(fn); err == nil && id > 0 {
			id := uint(id)
			name, err := GetProcessName(id)
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

func GetProcessName(id uint) (string, error) {
	content, err := ioutil.ReadFile(path.Join(ProcBase, strconv.Itoa(int(id)), "comm"))
	return strings.TrimSuffix(strings.ReplaceAll(string(content), "/", ""), "\n"), err
}
