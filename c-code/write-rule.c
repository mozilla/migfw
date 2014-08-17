/*
 * prints all the rules from all 
 * the chains
 * install iptables-dev package with dependencies (prefer synaptic package manger) :)
 */

#include <getopt.h>
#include <sys/errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <libiptc/libiptc.h>

#define IP_PARTS_NATIVE(n)      \
(unsigned int)((n)>>24)&0xFF,   \
(unsigned int)((n)>>16)&0xFF,   \
(unsigned int)((n)>>8)&0xFF,    \
(unsigned int)((n)&0xFF)


#define IP_PARTS(n) IP_PARTS_NATIVE(ntohl(n))

//print interface
static void print_iface(char letter, const char *iface, const unsigned char *mask, int invert)
{
    unsigned int i;

    if (mask[0] == 0)
        return;

    printf("-%c %s", letter, invert ? "! " : "");

    for (i = 0; i < IFNAMSIZ; i++) { //IFNAMSIZ is max size of buffer required to represent an interface
        if (mask[i] != 0) {
            if (iface[i] != '\0')
                printf("%c", iface[i]);
        } else {
            /* we can access iface[i-1] here, because
             * a few lines above we make sure that mask[0] != 0 */
            if (iface[i-1] != '\0')
                printf("+");
            break;
        }
    }

    printf(" ");
}


struct pprot {
    char *name;
    u_int8_t num;
};

static const struct pprot chain_protos[] = {
    { "tcp", IPPROTO_TCP },
    { "udp", IPPROTO_UDP },
    { "icmp", IPPROTO_ICMP },
    { "esp", IPPROTO_ESP },
    { "ah", IPPROTO_AH },
};

//print protocol
static void print_proto(u_int16_t proto, int invert)
{
    if (proto) {
        unsigned int i;
        const char *invertstr = invert ? "! " : "";

        for (i = 0; i < sizeof(chain_protos)/sizeof(struct pprot); i++)
            if (chain_protos[i].num == proto) {
                printf("-p %s%s ",invertstr, chain_protos[i].name);
                return;
            }

        printf("-p %s%u ", invertstr, proto);
    }
}


//print match segment
static int print_match(const struct ipt_entry_match *e, const struct ipt_ip *ip)
{
        printf("-m %s ", e->u.user.name);
    return 0;
}

/* print a given ip including mask if neccessary */
static void print_ip(char *prefix, u_int32_t ip, u_int32_t mask, int invert)
{
    if (!mask && !ip)
        return;

    printf("%s %s%u.%u.%u.%u", prefix, invert ? "! " : "", IP_PARTS(ip));

    if (mask != 0xffffffff)
        printf("/%u.%u.%u.%u ", IP_PARTS(mask));
    else
        printf(" ");
}

static void print_rule(const struct ipt_entry *e,struct xtc_handle *h, const char *chain, int counters)
{
    struct ipt_entry_target *t;
    const char *target_name;

    /* print counters */
    if (counters)
        printf("[%llu:%llu] ", e->counters.pcnt, e->counters.bcnt);

    /* print chain name */
    printf("-A %s ", chain);

    /* Print IP part. */
    print_ip("-s", e->ip.src.s_addr,e->ip.smsk.s_addr, e->ip.invflags & IPT_INV_SRCIP);

    print_ip("-d", e->ip.dst.s_addr, e->ip.dmsk.s_addr, e->ip.invflags & IPT_INV_DSTIP);

    print_iface('i', e->ip.iniface, e->ip.iniface_mask, e->ip.invflags & IPT_INV_VIA_IN);

    print_iface('o', e->ip.outiface, e->ip.outiface_mask,e->ip.invflags & IPT_INV_VIA_OUT);

    print_proto(e->ip.proto, e->ip.invflags & IPT_INV_PROTO);

    if (e->ip.flags & IPT_F_FRAG)
        printf("%s-f ", e->ip.invflags & IPT_INV_FRAG ? "! " : "");

    /* Print matchinfo part */
    if (e->target_offset) {
        IPT_MATCH_ITERATE(e, print_match, &e->ip);
    }

    /* Print target name */
    target_name = iptc_get_target(e, h);
    if (target_name && (*target_name != '\0'))
        printf("-j %s ", target_name);

    /* Print targinfo part */
    t = ipt_get_target((struct ipt_entry *)e);
    printf("\n");
}

int main(void)
{
  /* Use always this part for your programs .... From here ... **** */
    struct xtc_handle *h;
    const struct ipt_entry *e;
    const char *chain = NULL;
    const char *tablename = "filter";
    const int counters = 1;

    h = iptc_init(tablename);
    if(!h) {
        printf("Error initializing : %s \n", iptc_strerror(errno));
        exit(errno);
    }

    for (chain = iptc_first_chain(h); chain; chain = iptc_next_chain(h))  {
    	printf("%s\n", chain);
    	for (e = iptc_first_rule(chain, h); e; e = iptc_next_rule(e, h))  {
            print_rule(e, h, chain, counters);
        }
  	}

return 0;
} /* main */
