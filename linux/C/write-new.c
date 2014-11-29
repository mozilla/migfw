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
#include <xtables.h>

#define dbg(A) printf("%s %d\n",#A,(A) );
#define dbgs(A) printf("%s %s\n",#A,(A) );

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
	dbg(sizeof(m));
	temp->next = *headref;
	temp->match = m;
	*headref = temp;
	dbgs((*headref)->match->m->u.user.name);
}

void tcp_set(int smin, int smax, int dmin, int dmax) {
	// working fine
	struct xtables_match *match = xtables_find_match("tcp", XTF_LOAD_MUST_SUCCEED, NULL);
	match->m = (struct xt_entry_match *) malloc(XT_ALIGN(sizeof(struct xt_entry_match)) + match->size);
	match->m->u.match_size = XT_ALIGN(sizeof(struct xt_entry_match)) + match->size;
	dbg(match->m->u.match_size);
	strcpy(match->m->u.user.name, "tcp");
	struct xt_tcp *tcpinfo = (struct xt_tcp *) match->m->data;

	tcpinfo->spts[0] = smin;dbg(tcpinfo->spts[0]);
	tcpinfo->spts[1] = smax;dbg(tcpinfo->spts[1]);
	tcpinfo->dpts[0] = dmin;dbg(tcpinfo->dpts[0]);
	tcpinfo->dpts[1] = dmax;dbg(tcpinfo->dpts[1]);

	pushMatch(&matches, match);

}

void limit_set(int avg,int burst)
{
	avg /= 400;
	struct xtables_match *match = xtables_find_match("limit", XTF_LOAD_MUST_SUCCEED, NULL);
	match->m = (struct xt_entry_match *) malloc(XT_ALIGN(sizeof(struct xt_entry_match)) + match->size);
	match->m->u.match_size = XT_ALIGN(sizeof(struct xt_entry_match)) + match->size;
	dbg(match->m->u.match_size);
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
	dbg(match->m->u.match_size);
	strcpy(match->m->u.user.name, "physdev");
	struct xt_physdev_info * physdevinfo;
	physdevinfo = (struct xt_physdev_info *)match->m->data;
	strcpy(physdevinfo->physindev, physindev);
	memset(physdevinfo->in_mask, 0xFF, IFNAMSIZ);
	physdevinfo->bitmask = bitmask;

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


int main(){
	xtables_init();
	xtables_set_nfproto(NFPROTO_IPV4);

	tcp_set(0,890,67,678);
	limit_set(2000,10);
	// some features to be added in this 
	physdev_set("eth0","",1);

	struct ipt_entry *e;

	struct xt_standard_target *target = (struct xt_standard_target *)malloc(sizeof(struct xt_standard_target));
    target->target.u.target_size = sizeof(struct xt_standard_target);
	strcpy(target->target.u.user.name, "ACCEPT");
	
	struct ipt_ip ipdetails;

	// some assignments for the entry
	ipdetails.src.s_addr = inet_addr("145.145.1.0");
	ipdetails.smsk.s_addr= inet_addr("255.255.255.0");
	ipdetails.dst.s_addr = inet_addr("168.220.1.9");
	ipdetails.dmsk.s_addr= inet_addr("255.255.255.255");
	ipdetails.invflags = IPT_INV_SRCIP;
	ipdetails.proto = IPPROTO_TCP;
	strcpy(ipdetails.iniface, "eth0");

	// assignments over

	e = generate_entry(ipdetails, matches, target);

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

	return 0;
}