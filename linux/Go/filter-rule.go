package main

/*
#cgo pkg-config: libiptc
#cgo pkg-config: xtables
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <error.h>
#include <libiptc/libiptc.h>
#include <libiptc/libip6tc.h>
#include <xtables.h>


char buf[150];

void print_match_ipv4(struct xt_entry_match *m,struct ipt_ip *ip, int numeric, char *buf) {
	int fds[2];
  	pipe(fds);

  	if(!fork()) { //child element
  		close(fds[0]);
  		dup2(fds[1], STDOUT_FILENO);
		xtables_init();
		xtables_set_nfproto(NFPROTO_IPV4);
		const struct xtables_match *match = xtables_find_match(m->u.user.name, XTF_LOAD_MUST_SUCCEED, NULL);
	    if (match) {
	        if (match->print)
	            match->print(ip, m, numeric);
	        else
	            printf("%s ", match->name);
	    } else {
	        if (m->u.user.name[0])
	            printf("UNKNOWN match `%s' ", m->u.user.name);
	    }
	    exit(1);
	}
	else {
		close(fds[1]);
  		read(fds[0],buf,150);
	}
    
}
int match_iterate_wrapper_ipv4 (struct ipt_entry *e, unsigned int i) {
	memset(buf, 0, 150);
	struct xt_entry_match *m;
    m = (void *)e + i;
    i += m->u.match_size;
    print_match_ipv4(m , &e->ip, 0x0008, buf);
	return i;
}
int getSizeIptEntry() {
	return ((int) sizeof(struct ipt_entry)); 
}


void print_match_ipv6(struct xt_entry_match *m,struct ip6t_ip6 *ip, int numeric, char *buf) {
	int fds[2];
  	pipe(fds);

  	if(!fork()) { //child element
  		close(fds[0]);
  		dup2(fds[1], STDOUT_FILENO);
		xtables_init();
		xtables_set_nfproto(NFPROTO_IPV6);
	    const struct xtables_match *match = xtables_find_match(m->u.user.name, XTF_LOAD_MUST_SUCCEED, NULL);
	    if (match) {
	        if (match->print)
	            match->print(ip, m, numeric);
	        else
	            printf("%s ", match->name);
	    } else {
	        if (m->u.user.name[0])
	            printf("UNKNOWN match `%s' ", m->u.user.name);
	    }
	    exit(1);
	}
	else {
		close(fds[1]);
  		read(fds[0],buf,150);
	}
    
}
int match_iterate_wrapper_ipv6 (struct ip6t_entry *e, unsigned int i) {
	memset(buf, 0, 150);
	struct xt_entry_match *m;
    m = (void *)e + i;
    i += m->u.match_size;
    print_match_ipv6(m , &e->ipv6, 0x0008, buf);
	return i;
}
int getSizeIpt6Entry() {
	return ((int) sizeof(struct ip6t_entry)); 
}
*/
import "C"
import "errors"
import "net"
import "bytes"
import "os"
import "unsafe"
import "encoding/json"
import "strings"
import "strconv"
import "regexp"
//import "fmt"
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

//
type Counter struct {
	Packets uint64
	Bytes   uint64
}

type Match struct {
	Name string
	Options string
}

//
type Rule struct {
	Chain string
	Src    *net.IPNet
	Dest   *net.IPNet
	InDev  string
	OutDev string
	Not    struct {
		Src    bool
		Dest   bool
		InDev  bool
		OutDev bool
	}
	Matches []*Match
	Target string
	Counter
}

type Filter struct {
	Name string
	Options string
	InvFlag bool
}

var (
	ErrorCustomChain = errors.New("Custom chains dont have counters defined :/")
)

//
type IPTi interface {
	IsBuiltinChain(string) bool
	Chains() []string
	Close() error
	Counter(chain string) (Counter, error)
	Rules(chain string) []*Rule
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

func (s *IPT) Chains() []string {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	chains := []string{}

	for c := C.iptc_first_chain(s.h); c != nil; c = C.iptc_next_chain(s.h) {
		chains = append(chains, C.GoString(c))
	}

	return chains
}

func (s *IPT) IsBuiltinChain(chain string) bool {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	return int(C.iptc_builtin(cname, s.h)) != 0
}

func (s *IPT) Counter(chain string) (Counter, error) {
	var c Counter
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	if !s.IsBuiltinChain(chain) {
		return c, ErrorCustomChain
	}

	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	count := new(C.struct_xt_counters)
	_, err := C.iptc_get_policy(cname, count, s.h)

	if err != nil {
		return c, err
	}
	c.Packets = uint64(count.pcnt)
	c.Bytes = uint64(count.bcnt)

	return c, nil

}

func (s *IPT) Rules(chain string) []*Rule {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	rules := make([]*Rule, 0)

	for r := C.iptc_first_rule(cname, s.h); r != nil; r = C.iptc_next_rule(r, s.h) {
		c := new(Rule)

		// read counters
		c.Packets = uint64(r.counters.pcnt)
		c.Bytes = uint64(r.counters.bcnt)

		// read network interfaces
		c.InDev = C.GoString(&r.ip.iniface[0])
		c.OutDev = C.GoString(&r.ip.outiface[0])
		if r.ip.invflags&C.IPT_INV_VIA_IN != 0 {
			c.Not.InDev = true
		}
		if r.ip.invflags&C.IPT_INV_VIA_OUT != 0 {
			c.Not.OutDev = true
		}

		// read source ip and mask
		src := uint32(r.ip.src.s_addr)
		c.Src = new(net.IPNet)
		c.Src.IP = net.IPv4(byte(src&0xff),
							byte((src>>8)&0xff),
							byte((src>>16)&0xff),
							byte((src>>24)&0xff))
		mask := uint32(r.ip.smsk.s_addr)
		c.Src.Mask = net.IPv4Mask(byte(mask&0xff),
								byte((mask>>8)&0xff),
								byte((mask>>16)&0xff),
								byte((mask>>24)&0xff))
		if r.ip.invflags&C.IPT_INV_SRCIP != 0 {
			c.Not.Src = true
		}

		// read destination ip and mask
		dest := uint32(r.ip.dst.s_addr)
		c.Dest = new(net.IPNet)
		c.Dest.IP = net.IPv4(byte(dest&0xff),
							byte((dest>>8)&0xff),
							byte((dest>>16)&0xff),
							byte((dest>>24)&0xff))
		mask = uint32(r.ip.dmsk.s_addr)
		c.Dest.Mask = net.IPv4Mask(byte(mask&0xff),
								byte((mask>>8)&0xff),
								byte((mask>>16)&0xff),
								byte((mask>>24)&0xff))
		if r.ip.invflags&C.IPT_INV_DSTIP != 0 {
			c.Not.Dest = true
		}
		//read match 

		target_offset := int(r.target_offset)
		if(target_offset > 0) {
			for i := uint64(C.getSizeIptEntry()); int(i) < target_offset ;{
				i = uint64 (C.match_iterate_wrapper_ipv4(r, C.uint(i)))
				match := C.GoString(&C.buf[0])
				match = strings.Trim(match, " ")

				marr := strings.Fields(match)
				
				m := new(Match)
				m.Name = strings.ToLower(strings.TrimRight(marr[0],":"))
				m.Options = strings.Join(marr[1:]," ")
				c.Matches = append(c.Matches, m)
			}
		}

		// read target
		target := C.iptc_get_target(r, s.h)
		if target != nil {
			c.Target = C.GoString(target)
		}

		c.Chain = chain

		rules = append(rules, c)
	}

	return rules
}

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


// Filter Rules Functions Here
//

func FilterTarget(rule *Rule, option string, invFlag bool) bool {
	if(rule.Target == option){
		return (true != invFlag)
	} 
	return false
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

func FilterLimit(rule *Rule, options string, invFlag bool) bool{
	avg, burst := LimitValues(options)

	for _,match := range rule.Matches {
		if(match.Name == "limit"){
			avgR, burstR := LimitValues(match.Options)
			if(avgR <= avg && burstR <= burst){
				return (true != invFlag)
			}
		}
	} 
	return false

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

func FilterTCP(rule *Rule, options string, invFlag bool) bool {
	smin, smax, dmin, dmax := TcpPortRange(options)

	for _,match := range rule.Matches {
		if(match.Name == "tcp"){
			sminR, smaxR, dminR, dmaxR := TcpPortRange(match.Options)
			if(!(smax<=sminR || smin >= smaxR) && !(dmax<=dminR || dmin >= dmaxR)){
				return (true != invFlag)
			}
		}
	} 
	return false
}

func FilterString(rule *Rule, options string, invFlag bool) bool {
	regex := regexp.MustCompile(options)

	for _,match := range rule.Matches {
		if(match.Name == "string"){
			str := strings.Fields(options)
			if(regex.MatchString(str[1])){
				return (true != invFlag)
			}
		}
	} 
	return false
}


func FilterIPUtil(rule *Rule, iprange string, invFlag bool, srcDst bool ) bool { // srcDst true->src false->dst

	_,ip,_ := net.ParseCIDR(iprange)
	if(srcDst) {
		if(rule.Src.Contains(ip.IP) != rule.Not.Src) {
			return (true != invFlag);
		}
	} else {
		if(rule.Dest.Contains(ip.IP) != rule.Not.Dest) {
			return (true != invFlag);
		}
	}
	return false
}

func FilterIPSrc(rule *Rule, iprange string, invFlag bool) bool {
	return FilterIPUtil(rule, iprange, invFlag, true);
}


func FilterIPDst(rule *Rule, iprange string, invFlag bool) bool {
	return FilterIPUtil(rule, iprange, invFlag, false);
}

func FilterIFUtil(rule *Rule, interf string, invFlag bool, inOut bool ) bool { // inOut true->inDev false->outDev

	if(inOut) {
		if last := len(rule.InDev) - 1; last >= 0 && rule.InDev[last] == '+' {
	    	if( (rule.InDev[:last] == interf[:last]) != rule.Not.InDev) {
				return (true != invFlag);
			}
		} else if( (rule.InDev == interf) != rule.Not.InDev) {
			return (true != invFlag);
		}
	} else {
		if last := len(rule.OutDev) - 1; last >= 0 && rule.OutDev[last] == '+' {
	    	if( (rule.OutDev[:last] == interf[:last]) != rule.Not.OutDev) {
				return (true != invFlag);
			}
		} else if( (rule.OutDev == interf) != rule.Not.OutDev) {
			return (true != invFlag);
		}
	}
	return false

}

func FilterIFIn(rule *Rule, interf string, invFlag bool) bool {
	return FilterIFUtil(rule, interf, invFlag, true);
}

func FilterIFOut(rule *Rule, interf string, invFlag bool) bool {
	return FilterIFUtil(rule, interf, invFlag, false);
}


func FilterRule(rule *Rule, options string, invFlag bool, f func(*Rule, string, bool) bool) bool {
	return f(rule, options, invFlag)
}

func main() {

	funcMapFilter := map[string]func(*Rule, string, bool) bool {
		"iprange-src": FilterIPSrc,
		"iprange-dst": FilterIPDst,
		"interface-in": FilterIFIn,
		"interface-out": FilterIFOut,
        "tcp": FilterTCP,
        "string": FilterString,
        "limit": FilterLimit,
        "target": FilterTarget,
	}

	var ft = []Filter{{"tcp","spts:600:50000",false}}


	ipt, err := NewIPT("filter")

	if (err != nil) {
		panic("Error occured initializing filter table")
	}

	chains := ipt.Chains()
	for _,chain := range chains {
		
		rules := ipt.Rules(chain)
		var res []*Rule
		
		for _, rule := range rules {
			flag := true
			for _, filter := range ft{
				if(!FilterRule(rule, filter.Options, filter.InvFlag, funcMapFilter[filter.Name])){
					flag = false
					break
				}
			}
			if(flag){
				res = append(res, rule)
			}
		}
			
		byt, _ := json.Marshal(res)

		var out bytes.Buffer
		json.Indent(&out, byt, "=", "\t")
		out.WriteTo(os.Stdout)

	}
}
