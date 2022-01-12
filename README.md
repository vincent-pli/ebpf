# ebpf


## Quick start
1. Compile the C part code of ebpf   
  `clang -O2 -emit-llvm -c bpf.c -o - | llc -march=bpf -filetype=obj -o bpf.o`
  
2. Compile the GOLANG part  
  - for attaching    
  `go build ebpfAttach.go`
  - for detaching
  `go build ebpfDettach.go`

3. ./ebpfAttach -ip=8.8.8.8

4. ./ebpfDettach
  

## Reference
- https://github.com/libbpf/libbpf
- https://www.cnxct.com/lessons-using-ebpf-accelerating-cloud-native-zh/?f=2394
