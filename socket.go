package main

import (
	"errors"
	"fmt"
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
	procfs        Procfs
	socketINodeRe *regexp.Regexp
	ipv4Re        *regexp.Regexp
	ipv6Re        *regexp.Regexp
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
	Family     uint8
	State      TcpState
	LocalIp    string
	LocalPort  uint16
	RemoteIp   string
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

func (me procfsSocketProvider) newSocketInfo(family, localAddr, remoteAddr, state string) (SocketInfo, error) {
	r := SocketInfo{}
	var err error
	r.LocalIp, r.LocalPort, err = me.parseAddr(localAddr)
	if err != nil {
		return r, err
	}
	r.RemoteIp, r.RemotePort, err = me.parseAddr(remoteAddr)
	if err != nil {
		return r, err
	}
	r.str = fmt.Sprintf("%s_%s:%d->%s:%d_%s", family, r.LocalIp, r.LocalPort, r.RemoteIp, r.RemotePort, state)
	return r, nil
}

func (me procfsSocketProvider) parseAddr(addr string) (string, uint16, error) {
	ipAndPort := strings.Split(addr, ":")
	errMsg := errors.New("Not a valid IPv{4,6} address")
	if len(ipAndPort) != 2 {
		return "", 0, errMsg
	}
	port, err := strconv.ParseUint(ipAndPort[1], 16, 16)
	if err != nil {
		return "", 0, errMsg
	}
	ipAddr := ipAndPort[0]
	if len(ipAddr) == 8 {
		matches := me.ipv4Re.FindStringSubmatchIndex(ipAddr)
		ip := ""
		for i := 4; i >= 1; i-- {
			octet, err := strconv.ParseUint(
				string(me.ipv4Re.ExpandString([]byte{}, "$"+strconv.Itoa(i), ipAddr, matches)),
				16, 8)
			if err != nil {
				return "", 0, err
			}
			ip = ip + strconv.FormatUint(octet, 10) + "."
		}
		ip = ip[0 : len(ip)-1]
		return ip, uint16(port), nil

	}
	if len(ipAddr) == 32 {
		ip := me.ipv6Re.ReplaceAllString(ipAddr, "$1:$2:$3:$4:$5:$6:$7:$8")
		if ip == ipAddr {
			return "", 0, errors.New("Not a valid IPv6 address")
		}
		return ip, uint16(port), nil
	}
	return "", 0, errMsg
}

func NewProcfsSocketProvider(procfs Procfs) SocketProvider {
	socketINodeRe := regexp.MustCompile(`^(socket:\[(?P<inode>\d*)\]|\[0000\]:(?P<inode>\d*))$`)
	ipv4Re := regexp.MustCompile(`^([[:xdigit:]]{2})([[:xdigit:]]{2})([[:xdigit:]]{2})([[:xdigit:]]{2})$`)
	ipv6Re := regexp.MustCompile(`^([[:xdigit:]]{4})([[:xdigit:]]{4})([[:xdigit:]]{4})([[:xdigit:]]{4})([[:xdigit:]]{4})([[:xdigit:]]{4})([[:xdigit:]]{4})([[:xdigit:]]{4})$`)

	return procfsSocketProvider{procfs, socketINodeRe, ipv4Re, ipv6Re}
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
			processSockets[i].SocketInfo, err = me.newSocketInfo(tp, localAddr, remoteAddr, state)
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
	matches := me.socketINodeRe.FindStringSubmatchIndex(src)
	outStr := string(me.socketINodeRe.ExpandString([]byte{}, "$inode", src, matches))
	res, err := strconv.ParseUint(outStr, 10, 64)
	if err != nil {
		return 0, err
	}
	return res, nil
}
