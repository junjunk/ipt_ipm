/*
 * IPv6 src modification ip6tables target
 * IPv4 src/dst modification iptables target
 * (C) 2017 by Vadim Fedorenko <vadimjunk@gmail.com>
 */

#ifndef _IPT_TWIN_H
#define _IPT_TWIN_H

#define HASH_MASK ((1<<3)-1)

#include <linux/types.h>

union my_inet_addr {
	__u32		all[4];
	__be32		ip;
	__be32		ip6[4];
};

struct ipt_IPADDR_info {
	union my_inet_addr		ipaddr;
};


#endif
