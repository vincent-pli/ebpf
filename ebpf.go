package main

import (
	"encoding/binary"
	"net"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	rootCgroup	  = "/sys/fs/cgroup/unified"
	ebpfFS		  = "/sys/fs/bpf"
	bpfCodePath	 = "bpf.o"
	egressProgName  = "egress"
	ingressProgName = "ingress"
	blockedMapName  = "blocked_map"
)



func main() {
	unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})

	collec, err := ebpf.LoadCollection(bpfCodePath)
	if err != nil {
		fmt.Println(err)
		return
	}

	var ingressProg, egressProg *ebpf.Program
	var blockedMap *ebpf.Map
	ingressPinPath := filepath.Join(ebpfFS, ingressProgName)
	egressPinPath := filepath.Join(ebpfFS, egressProgName)
	blockedPinPath := filepath.Join(ebpfFS, blockedMapName)

	cgroup, err := os.Open(rootCgroup)
	if err != nil {
		return
	}
	defer cgroup.Close()

	ingressProg = collec.Programs[ingressProgName]
	ingressProg.Pin(ingressPinPath)

	egressProg = collec.Programs[egressProgName]
	egressProg.Pin(egressPinPath)

	blockedMap, _ = collec.Maps[blockedMapName]
	blockedMap.Pin(blockedPinPath)

	_, err = link.AttachCgroup(link.CgroupOptions{
		Path:	cgroup.Name(),
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: collec.Programs[ingressProgName],
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	_, err = link.AttachCgroup(link.CgroupOptions{
		Path:	cgroup.Name(),
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: collec.Programs[egressProgName],
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	blockedMap, err = ebpf.LoadPinnedMap(blockedPinPath, &ebpf.LoadPinOptions{})
	ip_bytes := net.ParseIP("8.8.8.8").To4()
	ip_int := binary.LittleEndian.Uint32(ip_bytes)
	if err = blockedMap.Put(&ip_int, &ip_int); err != nil {
		fmt.Println(err)
	}
}
