package main

import (
	"errors"
	"fmt"
	//	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type SocketProvider interface {
	GetSockets(processId uint) ([]ProcessSocket, error)
	GetProcessSocket(processId uint, socketId uint64) (ProcessSocket, error)
}

type procfsSocketProvider struct {
	procfs Procfs
	re     *regexp.Regexp
}

type TcpState uint8

const (
	ESTABLISHED TcpState = iota + 1
	SYN_SENT
	SYN_RECV
	FIN_WAIT
	FIN_WAIT2
	TIME_WAIT
	CLOSE
	CLOSE_WAIT
	LAST_ACK
	LISTEN
	CLOSING
	NEW_SYN_RECV
	MAX_STATES
)

type SocketInfo struct {
	Family uint8
	State  TcpState
	//	LocalIP    net.IP
	LocalPort uint16
	//	RemoteIP   net.IP
	RemotePort uint16

	str string
}

func (me SocketInfo) String() string {
	if me.str == "" {
		return "unknown"
	}
	return me.str
}

type ProcessSocket struct {
	Id         uint64
	INode      uint64
	ProcessId  uint
	SocketInfo SocketInfo
}

func (me ProcessSocket) String() string {
	return strconv.FormatUint(me.Id, 10) + "_" + me.SocketInfo.String()
}

func newSocketInfo(family, localAddr, remoteAddr, state string) (SocketInfo, error) {
	r := SocketInfo{}
	r.str = fmt.Sprintf("%s_%s->%s_%s", family, localAddr, remoteAddr, state)
	return r, nil
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

	return ProcessSocket{INode: inode, ProcessId: processId,
		Id: socketId, SocketInfo: SocketInfo{}}, nil
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
	err = me.fillSocketInfo(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (me procfsSocketProvider) fillSocketInfo(processSockets []ProcessSocket) error {
	sort.Slice(processSockets, func(i, j int) bool {
		return processSockets[i].INode < processSockets[j].INode
	})
	types := []string{"tcp", "udp", "tcp6", "udp6", "raw", "raw6", "udplite", "udplite6", "icmp", "icmp6"}
	for _, tp := range types {
		content, err := me.procfs.ReadFile("/net/" + tp)
		if err != nil {
			//			return err
			continue
		}
		lines := strings.Split(string(content), "\n")
		if len(lines) <= 1 {
			continue
		}
		for _, line := range lines[1 : len(lines)-1] {
			columns := strings.Split(removeSpacePaddings(line), " ")
			if len(columns) < 10 {
				return errors.New("Unknown format for proc file: /proc/net/" + tp)
			}
			localAddr := columns[1]
			remoteAddr := columns[2]
			state := columns[3]
			inode, err := strconv.ParseUint(columns[9], 10, 64)
			if err != nil {
				return err
			}
			i := sort.Search(len(processSockets),
				func(i int) bool { return processSockets[i].INode >= inode })
			if i >= len(processSockets) || processSockets[i].INode != inode {
				continue
			}
			processSockets[i].SocketInfo, err = newSocketInfo(tp, localAddr, remoteAddr, state)
			if err != nil {
				return err
			}

		}
	}
	// unix socket type goes here
	// netlink

	return nil
}

func removeSpacePaddings(line string) string {
	var prev = ' '
	remover := func(r rune) rune {
		if r != ' ' {
			prev = r
			return r
		}
		if prev == ' ' {
			return -1
		}
		prev = r
		return r
	}
	return strings.Map(remover, line)
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
