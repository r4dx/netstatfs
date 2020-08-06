package main

import "errors"
import "fmt"
import "github.com/google/gopacket/pcap"
import "io"
import "net"
import "strings"
import "syscall"
import "time"

type Sniffer interface {
	Close()
	Data(size uint32) chan []byte
}

type GoPacketSniffer struct {
	handle  *pcap.Handle
	channel chan []byte
}

func NewSniffer(si SocketInfo) (Sniffer, error) {
	var maxEtherSize int32 = 1522
	promisc := true
	handle, err := pcap.OpenLive(si.NI, maxEtherSize, promisc, pcap.BlockForever)
	if err != nil {
		return GoPacketSniffer{}, err
	}
	var filter string
	filter, err = socketInfoToBPFFilter(si)
	if err != nil {
		return GoPacketSniffer{}, err
	}
	err = handle.SetBPFFilter(filter)
	if err != nil {
		handle.Close()
		return GoPacketSniffer{}, err
	}
	return GoPacketSniffer{handle, nil}, nil
}

func socketInfoToBPFFilter(si SocketInfo) (string, error) {
	networkToFilter := map[string]string{
		"tcp":  "tcp",
		"tcp6": "tcp",
		"udp":  "udp",
		"udp6": "udp",
	}
	if proto, exists := networkToFilter[si.Network]; exists {
		return fmt.Sprintf("%s port %d", proto, si.LocalPort), nil
	}
	return "",
		errors.New(si.Network + " network type is not supported")
}

func (me GoPacketSniffer) dataToChannel() {
	defer close(me.channel)

	for {
		data, _, err := me.handle.ReadPacketData()
		if err == nil {
			me.channel <- data
			continue
		}
		if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
			continue
		}
		if err == syscall.EAGAIN {
			continue
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF ||
			err == io.ErrNoProgress || err == io.ErrClosedPipe || err == io.ErrShortBuffer ||
			err == syscall.EBADF ||
			strings.Contains(err.Error(), "use of closed file") {
			break
		}

		time.Sleep(time.Millisecond * time.Duration(5))
	}
}
func (me GoPacketSniffer) Data(size uint32) chan []byte {
	if me.channel == nil {
		me.channel = make(chan []byte, 1000)
		go me.dataToChannel()
	}
	return me.channel
}
func (me GoPacketSniffer) Close() {
	me.handle.Close()
}
