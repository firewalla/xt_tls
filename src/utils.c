

#include <linux/inet.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/types.h>
#include <net/net_namespace.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>


#include "utils.h"
#include "xt_tls.h"

static char *sm_prefix = "*.";
static size_t sm_prefix_len = 2;
// The proc-fs subdirectory for hostsets
struct proc_dir_entry *proc_fs_dir = NULL;
struct proc_dir_entry *proc_fs_hostset_dir = NULL;
unsigned int g_max_MTU = 1500; // set default mtu to 1500

void print_hex(const char *msg, const u8 *buf, int len) {
#ifdef DEBUG
	int i;
	if (len > 65536) {
		// pr_debug("abnormal len,%s: len=%d\n", msg, len);
		printk(KERN_DEBUG pr_fmt("abnormal len,%s: len=%d\n"), msg,
		       len);
		return;
	}
	// pr_debug("%s: ", msg);
	printk(KERN_DEBUG pr_fmt("%s: "), msg);
	for (i = 0; i < len; i++) {
		// pr_cont("%02X ", buf[i]);
		printk(KERN_CONT "%02X ", buf[i]);
	}
	printk(KERN_DEBUG "\n");
#endif
}

// RETURN VALUE
//   true - matched
//   false - unmatched
// Example:
//   str => www.google.com
//   suffix => google.com
//   str should end with ".google.com"
bool match_dot_suffix(const char *hostname, const char *suffix) {
	size_t hlen, slen;

	if (!hostname || !suffix) return false;

	hlen = strlen(hostname);
	slen = strlen(suffix);

	if (slen + 1 > hlen)  // 1 is the dot
		return false;

	if (strncmp(hostname + hlen - slen, suffix, slen) != 0) {
		return false;
	}

	if (hostname[hlen - slen - 1] == '.') {
		return true;
	}

	return false;
}

// pattern example: *.google.com, google.com, facebook.com
// host: www.google.com, www.facebook.com
// RETURN
//   - true - matched
//   - false - unmatched
bool combo_match(const char *pattern, const char *host) {
	bool suffix_matching = false;
	size_t offset = 0;  // pattern offset

	if (strncmp(pattern, sm_prefix, sm_prefix_len) == 0) {
		suffix_matching = true;
		offset = sm_prefix_len;
	}

#ifdef XT_TLS_DEBUG
	pr_info("combo match: pattern %s, host %s, suffix_matching %d\n",
	        pattern, host, suffix_matching);
#endif

	// use exact match first
	if (strcmp(pattern + offset, host) == 0) {
		return true;
	}

	// if exact match doesn't match, try suffix matching if suffix_matching
	// is true
	if (suffix_matching) {
		return match_dot_suffix(host, pattern + offset);
	}

	return false;
}

int create_procfs(char *mod_name) {
	if (!proc_fs_dir) {  // skip if already created, unlikely to happen
		proc_fs_dir = proc_mkdir(mod_name, init_net.proc_net);
		if (!proc_fs_dir) {
			pr_err("Cannot create /proc/net/%s for this module\n",
			       mod_name);
			return -EFAULT;
		}  // if
	}  // if

	if (!proc_fs_hostset_dir) {
		proc_fs_hostset_dir =
		    proc_mkdir(PROC_FS_HOSTSET_SUBDIR, proc_fs_dir);
		if (!proc_fs_hostset_dir) {
			pr_err(
			    "Cannot create /proc/net/%s/%s for this module\n",
			    mod_name, PROC_FS_HOSTSET_SUBDIR);
			return -EFAULT;
		}  // if
	}

	return 0;
}  // create_procfs

void cleanup_procfs(char *mod_name) {
	// delete everything under /proc/net/xt_tls
	remove_proc_subtree(mod_name, init_net.proc_net);

	proc_fs_hostset_dir = NULL;
	proc_fs_dir = NULL;
}  // cleanup_procfs

unsigned int get_max_MTU(void) {
	return g_max_MTU;
}

void init_max_MTU(void) {
	struct net_device *dev;
	unsigned int max_MTU = 0;

	rtnl_lock();
	for_each_netdev(&init_net, dev) {
		pr_debug("dev %s, mtu %d\n", dev->name, dev->mtu);
		if (dev->type == ARPHRD_ETHER && 
		    dev->type != ARPHRD_LOOPBACK &&
		    dev->mtu > max_MTU) { // only consider ethernet devices
			max_MTU = dev->mtu;
		}
	}
	rtnl_unlock();

	if (max_MTU == 0 || max_MTU > 65535) {
		pr_err("Invalid max_MTU %d, use default value 1500\n", max_MTU);
		max_MTU = 1500;
	}
	g_max_MTU = max_MTU;
}

void print_packet_info_and_hostname(const struct sk_buff *skb, const struct xt_action_param *par, char * slogan, char *hostname)
{
    struct tcphdr _tcph, *tcp_header;
    struct udphdr _udph, *udp_header;
    unsigned int src_port = 0, dst_port = 0;
    u8 protocol;
    int family = par->match->family;
    unsigned int thoff = par->thoff;

    if (family == NFPROTO_IPV4) {
	struct iphdr *ip_header = ip_hdr(skb);
        protocol = ip_header->protocol;

        if (protocol == IPPROTO_TCP) {
	    tcp_header = skb_header_pointer(skb, thoff,
		  sizeof(_tcph), &_tcph);
	    if (!tcp_header)
		return;

            src_port = ntohs(tcp_header->source);
            dst_port = ntohs(tcp_header->dest);
        } else if (protocol == IPPROTO_UDP) {
    	    udp_header = skb_header_pointer(skb, thoff,
                  sizeof(_udph), &_udph);
	    if (!udp_header)
		return;
            src_port = ntohs(udp_header->source);
            dst_port = ntohs(udp_header->dest);
        } else {
	    pr_debug("Unsupported protocol %d\n", protocol);
	    return;
	}

	printk("[%s]:{\"src_addr\":\"%pI4\", \"dst_addr\":\"%pI4\", \"src_port\":%u, \"dst_port\":%u, \"protocol\":\"%s\", \"hostname\":\"%s\"}\n", 
		slogan, &ip_header->saddr, &ip_header->daddr, src_port, dst_port, protocol == IPPROTO_TCP ? "TCP" : "UDP", hostname);
    } else if (family == NFPROTO_IPV6) {
	struct ipv6hdr *ipv6_header = ipv6_hdr(skb);
        protocol = ipv6_header->nexthdr;

        if (protocol == IPPROTO_TCP) {
	    tcp_header = skb_header_pointer(skb, thoff,
		  sizeof(_tcph), &_tcph);
	    if (!tcp_header)
		return;

            src_port = ntohs(tcp_header->source);
            dst_port = ntohs(tcp_header->dest);
        } else if (protocol == IPPROTO_UDP) {
	    udp_header = skb_header_pointer(skb, thoff,
		sizeof(_udph), &_udph);
            if (!udp_header)
		return;

	    src_port = ntohs(udp_header->source);
	    dst_port = ntohs(udp_header->dest);
	} else {
	    pr_debug("Unsupported protocol %d\n", protocol);
	    return;
	}

	printk("[%s]:{\"src_addr\":\"%pI6c\", \"dst_addr\":\"%pI6c\", \"src_port\":%u, \"dst_port\":%u, \"protocol\":\"%s\", \"hostname\":\"%s\"}\n", 
		slogan, &ipv6_header->saddr, &ipv6_header->daddr, src_port, dst_port, protocol == IPPROTO_TCP ? "TCP" : "UDP", hostname);
    }
}