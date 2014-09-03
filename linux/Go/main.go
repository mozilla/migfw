package main

import "fmt"

// #cgo LDFLAGS: -liptc
// #cgo LDFLAGS: -lip4tc
// #cgo LDFLAGS: -lip6tc
// #cgo LDFLAGS: -ldl
// #include "../C/migfw_helper.h"
import "C"

type ip_details struct {
    src_ip string
    src_subnet string
    dest_ip string
    dest_subnet string
    iniface string
}

type protocol struct {
    name string
    src_ports [2]int
    dest_ports [2]int
}

func main() {
	// VARIABLE DECLARATIONS //
	// chain := "INPUT"
	tablename := "filter"
	ip := ip_details {"157.145.1.3","255.255.255.255","168.220.1.9","255.255.255.255","eth0"}
	proto := protocol {"tcp", [2]int{0,80}, [2]int{0,51201}}
	jump := "ACCEPT"
	// VARIABLE DECLARATIONS //
	var detail = C.struct_details{}; // assigning values to the structure
	// detail.chain = chain
	detail.tablename = C.CString(tablename)

	detail.ip.src_ip = C.CString(ip.src_ip)
	detail.ip.src_subnet = C.CString(ip.src_subnet)
	detail.ip.dest_ip = C.CString(ip.dest_ip)
	detail.ip.dest_subnet = C.CString(ip.dest_subnet)
	detail.ip.iniface = C.CString(ip.iniface)

	detail.proto.name = C.CString(proto.name)
	detail.proto.src_ports[0] = C.uint(proto.src_ports[0])
	detail.proto.src_ports[1] = C.uint(proto.src_ports[1])
	detail.proto.dest_ports[0] = C.uint(proto.dest_ports[0])
	detail.proto.dest_ports[1] = C.uint(proto.dest_ports[1])

	detail.jump = C.CString(jump)
	// fmt.Println(detail)
	ret_val := C.write_rule(&detail)
	fmt.Println(ret_val)
}