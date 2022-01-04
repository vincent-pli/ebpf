package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

const (
	rootCgroup      = "/sys/fs/cgroup/unified"
	ebpfFS          = "/sys/fs/bpf"
	egressProgName  = "egress"
	ingressProgName = "ingress"
	blockedMapName  = "blocked_map"
)

func main() {
	var ingressProg, egressProg *ebpf.Program

	ingressPinPath := filepath.Join(ebpfFS, ingressProgName)
	egressPinPath := filepath.Join(ebpfFS, egressProgName)
	blockedPinPath := filepath.Join(ebpfFS, blockedMapName)

	ingressProg, err := ebpf.LoadPinnedProgram(ingressPinPath, &ebpf.LoadPinOptions{})
	if err != nil {
		fmt.Println(err)
		return
	}
	egressProg, err = ebpf.LoadPinnedProgram(egressPinPath, &ebpf.LoadPinOptions{})
	if err != nil {
		fmt.Println(err)
		return
	}

	cgroup, err := os.Open(rootCgroup)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer cgroup.Close()

	ingressProg.Detach(int(cgroup.Fd()), ebpf.AttachCGroupInetIngress, 0)
	egressProg.Detach(int(cgroup.Fd()), ebpf.AttachCGroupInetEgress, 0)

	os.Remove(ingressPinPath)
	os.Remove(egressPinPath)
	os.Remove(blockedPinPath)
}
