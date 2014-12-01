package main

/*
#cgo pkg-config: libiptc
#cgo pkg-config: xtables
#include <stdio.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <error.h>
#include <libiptc/libiptc.h>
#include <libiptc/libip6tc.h>
#include <linux/netfilter/xt_tcpudp.h>
#include <linux/netfilter/xt_limit.h>
#include <linux/netfilter/xt_physdev.h>
#include <linux/netfilter/xt_string.h>
#include <xtables.h>

static struct xtables_rule_match *matches = NULL;

struct ipt_ip assign_ip_details(struct ipt_ip ipdetails)
{
	static struct ipt_ip ipdet;
	ipdet.src.s_addr = ipdetails.src.s_addr;// inet_addr("272.145.1.0");
	ipdet.smsk.s_addr= ipdetails.smsk.s_addr;// inet_addr("255.255.255.255");
	ipdet.dst.s_addr = ipdetails.dst.s_addr;//inet_addr("168.220.1.9");
	ipdet.dmsk.s_addr= ipdetails.dmsk.s_addr;//inet_addr("255.255.255.255");
	ipdet.invflags = ipdetails.invflags;//IPT_INV_SRCIP;
	ipdet.proto = ipdetails.proto;//IPPROTO_TCP;
	strcpy(ipdet.iniface,ipdetails.iniface);
	return ipdet;
}

void pushMatch(struct xtables_rule_match **headref, struct xtables_match *m) {
	struct xtables_rule_match *temp = (struct xtables_rule_match *) malloc(sizeof(struct xtables_rule_match));
	temp->next = *headref;
	temp->match = m;
	*headref = temp;
	//dbgs((*headref)->match->m->u.user.name);
}

void tcp_set(int smin, int smax, int dmin, int dmax) {
	// working fine
	struct xtables_match *match = xtables_find_match("tcp", XTF_LOAD_MUST_SUCCEED, NULL);
	match->m = (struct xt_entry_match *) malloc(XT_ALIGN(sizeof(struct xt_entry_match)) + match->size);
	match->m->u.match_size = XT_ALIGN(sizeof(struct xt_entry_match)) + match->size;
	//dbg(match->m->u.match_size);
	strcpy(match->m->u.user.name, "tcp");
	struct xt_tcp *tcpinfo = (struct xt_tcp *) match->m->data;

	tcpinfo->spts[0] = smin;//dbg(tcpinfo->spts[0]);
	tcpinfo->spts[1] = smax;//dbg(tcpinfo->spts[1]);
	tcpinfo->dpts[0] = dmin;//dbg(tcpinfo->dpts[0]);
	tcpinfo->dpts[1] = dmax;//dbg(tcpinfo->dpts[1]);

	pushMatch(&matches, match);

}

void limit_set(int avg,int burst)
{
	avg /= 400;
	struct xtables_match *match = xtables_find_match("limit", XTF_LOAD_MUST_SUCCEED, NULL);
	match->m = (struct xt_entry_match *) malloc(XT_ALIGN(sizeof(struct xt_entry_match)) + match->size);
	match->m->u.match_size = XT_ALIGN(sizeof(struct xt_entry_match)) + match->size;
	//dbg(match->m->u.match_size);
	strcpy(match->m->u.user.name, "limit");
	struct xt_rateinfo *rateinfo=(struct xt_rateinfo *) match->m->data;
	rateinfo->avg = avg;
	rateinfo->burst = burst;
	pushMatch(&matches,match);
}

void physdev_set(const char physindev[IFNAMSIZ],const char physoutdev[IFNAMSIZ], __u8 bitmask)
{
	// will have to discuss it and redesign this function
	struct xtables_match *match = xtables_find_match("physdev", XTF_LOAD_MUST_SUCCEED, NULL);
	match->m = (struct xt_entry_match *) malloc(XT_ALIGN(sizeof(struct xt_entry_match)) + match->size);
	match->m->u.match_size = XT_ALIGN(sizeof(struct xt_entry_match)) + match->size;
	//dbg(match->m->u.match_size);
	strcpy(match->m->u.user.name, "physdev");
	struct xt_physdev_info * physdevinfo;
	physdevinfo = (struct xt_physdev_info *)match->m->data;
	strcpy(physdevinfo->physindev, physindev);
	memset(physdevinfo->in_mask, 0xFF, IFNAMSIZ);
	physdevinfo->bitmask = bitmask;

	pushMatch(&matches,match);
}

void string_set(const char *pattern, const char *algo) {
	struct xtables_match *match = xtables_find_match("physdev", XTF_LOAD_MUST_SUCCEED, NULL);
	match->m = (struct xt_entry_match *) malloc(XT_ALIGN(sizeof(struct xt_entry_match)) + match->size);
	match->m->u.match_size = XT_ALIGN(sizeof(struct xt_entry_match)) + match->size;

	strcpy(match->m->u.user.name, "string");

	struct xt_string_info *info = (struct xt_string_info *) match->m->data;
	info->to_offset = UINT16_MAX;
	if (strlen(pattern) <= XT_STRING_MAX_PATTERN_SIZE) {
		strncpy(info->pattern, pattern, XT_STRING_MAX_PATTERN_SIZE);
		info->patlen = strnlen(pattern, XT_STRING_MAX_PATTERN_SIZE);
	}
	if (strlen(algo) <= XT_STRING_MAX_ALGO_NAME_SIZE) {
		strncpy(info->algo, algo, XT_STRING_MAX_ALGO_NAME_SIZE);
	}

	pushMatch(&matches,match);
}

static struct ipt_entry * generate_entry( struct ipt_ip ipdetails, struct xtables_rule_match *matches, struct xt_standard_target *target) {
	unsigned int size;
	struct xtables_rule_match *matchp;
	static struct ipt_entry *e;

	size = sizeof(struct ipt_entry);
	for (matchp = matches; matchp; matchp = matchp->next)
		size += matchp->match->m->u.match_size;

	// e = xtables_malloc(size + target->target.u.target_size);
	// xtables_malloc returns an allocated void *

	e = calloc(1,size + target->target.u.target_size);

	e->ip = assign_ip_details(ipdetails);
	
	e->nfcache = 0;
	e->target_offset = size;
	e->next_offset = size + target->target.u.target_size;

	size = 0;
	for (matchp = matches; matchp; matchp = matchp->next) {
		memcpy(e->elems + size, matchp->match->m, matchp->match->m->u.match_size);
		size += matchp->match->m->u.match_size;
	}

	memcpy(e->elems + size, target, target->target.u.target_size);

	return e;
}

struct ipt_entry * CreateRuleIPv4(char *srcip, char *srcmask, char *dstip, char *dstmask, char *indev, char *outdev, char *tt){
	xtables_init();
	xtables_set_nfproto(NFPROTO_IPV4);

	struct ipt_entry *e;

	struct xt_standard_target *target = (struct xt_standard_target *)malloc(sizeof(struct xt_standard_target));
    target->target.u.target_size = sizeof(struct xt_standard_target);
	strcpy(target->target.u.user.name, tt);
	
	struct ipt_ip ipdetails;

	// some assignments for the entry
	ipdetails.src.s_addr = inet_addr(srcip);
	ipdetails.smsk.s_addr= inet_addr(srcmask);
	ipdetails.dst.s_addr = inet_addr(dstip);
	ipdetails.dmsk.s_addr= inet_addr(dstmask);
	//ipdetails.invflags = IPT_INV_SRCIP;
	//ipdetails.proto = IPPROTO_TCP;
	strcpy(ipdetails.iniface, indev);

	// assignments over

	e = generate_entry(ipdetails, matches, target);
	

	// bring this code to GO --->

	struct xtc_handle *h;
	const ipt_chainlabel chain = "INPUT";
	const char * tablename = "filter";
	h = iptc_init(tablename);
	if ( !h )
	{
		printf("Error initializing: %s\n", iptc_strerror(errno));
		exit(errno);
	}

	//analogous to “iptables -A INPUT” part of our desirable rule + the rule itself
	//inside of the e struct
	int x = iptc_append_entry(chain, e, h);
	if (!x)
	{
		printf("Error append_entry: %s\n", iptc_strerror(errno));
		exit(errno);
	}

	int y = iptc_commit(h);
	if (!y)
	{
		printf("Error commit: %s\n", iptc_strerror(errno));
		exit(errno);
	}


	return e;
}




*/
import "C"
// import "errors"
// import "fmt"
import "net"
// import "bytes"
// import "os"
import "unsafe"
// import "encoding/json"
import "strings"
//import "reflect"

/**
 * Declaration of structures and interfaces
 *
 *
 *
 */

//
type IPT struct {
	h *C.struct_xtc_handle
}

//
type IP6T struct {
	h *C.struct_xtc_handle
}

type Filter struct {
	Name string
	Options string
	InvFlag bool
}

type IPTi interface {
	Close() error
	Zero(chain string) error
}
// Make a snapshot of the current iptables rules
func NewIPT(table string) (IPTi, error) {
	cname := C.CString(table)
	defer C.free(unsafe.Pointer(cname))
	s := new(IPT)
	h, err := C.iptc_init(cname)

	if err != nil {
		return nil, err
	}
	s.h = h
	return s, nil
}


// func (s *IPT) Rules(chain string) []*Rule {
// 	if s.h == nil {
// 		panic("trying to use libiptc handle after Close()")
// 	}

// 	cname := C.CString(chain)
// 	defer C.free(unsafe.Pointer(cname))

// 	rules := make([]*Rule, 0)

// 	for r := C.iptc_first_rule(cname, s.h); r != nil; r = C.iptc_next_rule(r, s.h) {
// 		c := new(Rule)

// 		// read counters
// 		c.Packets = uint64(r.counters.pcnt)
// 		c.Bytes = uint64(r.counters.bcnt)

// 		// read network interfaces
// 		c.InDev = C.GoString(&r.ip.iniface[0])
// 		c.OutDev = C.GoString(&r.ip.outiface[0])
// 		if r.ip.invflags&C.IPT_INV_VIA_IN != 0 {
// 			c.Not.InDev = true
// 		}
// 		if r.ip.invflags&C.IPT_INV_VIA_OUT != 0 {
// 			c.Not.OutDev = true
// 		}

// 		// read source ip and mask
// 		src := uint32(r.ip.src.s_addr)
// 		c.Src = new(net.IPNet)
// 		c.Src.IP = net.IPv4(byte(src&0xff),
// 							byte((src>>8)&0xff),
// 							byte((src>>16)&0xff),
// 							byte((src>>24)&0xff))
// 		mask := uint32(r.ip.smsk.s_addr)
// 		c.Src.Mask = net.IPv4Mask(byte(mask&0xff),
// 								byte((mask>>8)&0xff),
// 								byte((mask>>16)&0xff),
// 								byte((mask>>24)&0xff))
// 		if r.ip.invflags&C.IPT_INV_SRCIP != 0 {
// 			c.Not.Src = true
// 		}

// 		// read destination ip and mask
// 		dest := uint32(r.ip.dst.s_addr)
// 		c.Dest = new(net.IPNet)
// 		c.Dest.IP = net.IPv4(byte(dest&0xff),
// 							byte((dest>>8)&0xff),
// 							byte((dest>>16)&0xff),
// 							byte((dest>>24)&0xff))
// 		mask = uint32(r.ip.dmsk.s_addr)
// 		c.Dest.Mask = net.IPv4Mask(byte(mask&0xff),
// 								byte((mask>>8)&0xff),
// 								byte((mask>>16)&0xff),
// 								byte((mask>>24)&0xff))
// 		if r.ip.invflags&C.IPT_INV_DSTIP != 0 {
// 			c.Not.Dest = true
// 		}
// 		//read match 

// 		target_offset := int(r.target_offset)
// 		if(target_offset > 0) {
// 			for i := uint64(C.getSizeIptEntry()); int(i) < target_offset ;{
// 				i = uint64 (C.match_iterate_wrapper_ipv4(r, C.uint(i)))
// 				match := C.GoString(&C.buf[0])
// 				match = strings.Trim(match, " ")

// 				marr := strings.Fields(match)
				
// 				m := new(Match)
// 				m.Name = strings.ToLower(strings.TrimRight(marr[0],":"))
// 				m.Options = strings.Join(marr[1:]," ")
// 				c.Matches = append(c.Matches, m)
// 			}
// 		}

// 		// read target
// 		target := C.iptc_get_target(r, s.h)
// 		if target != nil {
// 			c.Target = C.GoString(target)
// 		}

// 		c.Chain = chain

// 		rules = append(rules, c)
// 	}

// 	return rules
// }

func (s *IPT) Zero(chain string) error {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	ret, err := C.iptc_zero_entries(cname, s.h)

	if err != nil || ret != 1 {
		return err
	}

	return nil
}

// commit and free resources
func (s *IPT) Close() error {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	ret, err := C.iptc_commit(s.h)
	if err != nil || ret != 1 {
		return err
	}

	C.iptc_free(s.h)
	s.h = nil

	return nil
}

func (m IPMask) String() string {
	s := ""
	for i, value := range m.ip {
		s+= Itoa(int(value))
		if(i < len(m)-1){
			s+="."
		}
	}
	return s
}


func TcpPortRange(options string) (int64, int64, int64, int64) {
	var smin, smax, dmin, dmax int64 = 0, 65535, 0, 65535

	for _, option := range strings.Fields(options) {
		opt := strings.Split(option,":")
		if(opt[0]=="spts") {
			last := len(opt) - 1;
			min, _ := strconv.ParseInt(opt[1],10,64)
			max, _ := strconv.ParseInt(opt[last],10,64)
			if(smin < min ) {
				smin = min
			}
			if(max < smax  && max != 0) {
				smax = max
			}
		}
		if(opt[0]=="dpts") {
			last := len(opt) - 1;
			min, _ := strconv.ParseInt(opt[1],10,64)
			max, _ := strconv.ParseInt(opt[last],10,64)
			if(dmin < min ) {
				dmin = min
			}
			if(max < dmax && max != 0) {
				dmax = max
			}
		}
	}
	return smin, smax, dmin, dmax
}

func MatchTCP(options string) {
	smin, smax, dmin, dmax := TcpPortRange(options)
	C.tcp_set(C.uint(smin), C.uint(smin), C.uint(dmin), C.uint(dmax))
}

func LimitValues(options string) (int64, int64){
	var avg, burst int64 = 0,65535
	params := strings.Fields(options)
	for i, param := range params{
		if(param == "avg" && i < len(params)){
			valueArr:=strings.Split(params[i+1],"/")
			avg,_ = strconv.ParseInt(valueArr[0],10,64)
			if(len(valueArr) < 2 && valueArr[1]=="min"){
				avg *= 60
			} else if(len(valueArr) < 2 && valueArr[1]=="hour"){
				avg *= 3600
			}
		}
		if(param == "burst" && i < len(params)){
			burst,_ = strconv.ParseInt(params[i+1],10,64)
		}
	}
	return avg, burst
}

func MatchLimit(options string) {
	avg, burst := LimitValues(options)
	C.limit_set(C.uint(avg), C.uint(burst))
}

func MatchTCP(options string) {
	smin, smax, dmin, dmax := TcpPortRange(options)
	C.tcp_set(C.uint(smin), C.uint(smin), C.uint(dmin), C.uint(dmax))
}

func MatchString(options string) {
	option := strings.Fields(options)
	pattern := ""
	algo := "RBK"
	for i, value := range option{
		if(value == "match") {
			pattern = strings.Trim(option[i+1], "\"")
		}
		if(value == "algo") {
			algo = option[i+1]	
		}
	}
	C.string_set(C.CString(pattern), C.CString(algo))
}


func InsertMatch(options string, f func(string)){
	f(options)
}
func main() {
    funcMapMatch := map[string]func(string){
        "tcp": MatchTCP,
        "string": MatchString,
        "limit": MatchLimit,
	}

	var ft = []Filter{{"tcp","spts:600:50000",false}}
	ipt, err := NewIPT("filter")

	if (err != nil) {
		panic("Error occured initializing filter table")
	}

	SrcIp := "0.0.0.0"
	SrcMask := "0.0.0.0"
	SrcInvFlag := false
	
	DstIp := "0.0.0.0"
	DstMask := "0.0.0.0"
	DstInvFlag := false

	InDev := ""
	InDevInvFlag := false
	OutDev := ""
	OutDevInvFlag := false

	Target := "ACCEPT"

	for _, filter := range ft{
		if(filter.Name == "iprange-src"){
			_,src,_ := net.ParseCIDR(filter.Options)
			SrcIp = src.Ip.String()
			SrcMask = src.Mask.String()
		}
		if(filter.Name == "iprange-dst") {
			_,dst,_ := net.ParseCIDR(filter.Options)
			DstIp = dst.Ip.String()
			DstMask = dst.Mask.String()	
		} 
		if(filter.Name == "interface-in") {
			InDev = filter.Options
		} 
		if(filter.Name == "interface-in") {
			OutDev = filter.Options
		}
		if(filter.Name == "target") {
			Target = filter.Options
		} 

		InsertMatch(filter.options, funcMapMatch[filter.Name]);
	}

	r:= C.CreateRuleIPv4(SrcIp, SrcMask, DstIp, DstMask, InDev, OutDev, Target)
}
