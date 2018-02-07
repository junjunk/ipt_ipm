/*
 * IPv6 src modification ip6tables target
 * IPv4 dst/src modification iptables target
 * (C) 2017 by Vadim Fedorenko <vadimjunk@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/tcp.h>

#include <linux/netfilter/x_tables.h>
#include "ipt_IPADDR.h"

MODULE_AUTHOR("Vadim Fedorenko <vadimjunk@gmail.com>");
MODULE_DESCRIPTION("Xtables: IPADDRESS modification target");
MODULE_LICENSE("GPL");

static unsigned int
ip6spoof_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct ipv6hdr *iph6;
	struct iphdr *iph;

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;
	iph6 = ipv6_hdr(skb);
	if (iph6 && iph6->nexthdr == 4)
	{
		iph = ipip_hdr(skb);
		iph6->saddr.s6_addr32[2] = iph->saddr & HASH_MASK;
		/*
		The patch "ipv6: fix flow labels when the traffic class is non-0"
		https://patchwork.ozlabs.org/patch/721740/
		fixes flow label id generation, that's why all ip-in-ip6 packets
		will have the same flow_label and we cannot use it for spreading
		source ip

		this patch was included in Canonical 4.4.0-83 kernel
		*/
		//iph6->saddr.s6_addr32[2] = iph6->flow_lbl[0] & HASH_MASK;
	}
	return XT_CONTINUE;
}

static unsigned int
ipsrc_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *iph;
	const struct ipt_IPADDR_info *info = par->targinfo;
	struct udphdr *udph;
	struct tcphdr *tcph;
	__u32 len;
	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;
	if (skb_linearize(skb)) 
		return NF_DROP;

	iph = ip_hdr(skb);
	if (iph && iph->protocol)
	{
		iph->saddr = info->ipaddr.ip;
        	/* Calculation of IP header checksum */
	        iph->check = 0;
		len = (skb->len - (iph->ihl << 2));
		switch (iph->protocol)
		{
			case IPPROTO_TCP:
				tcph = (struct tcphdr *) (iph + (iph->ihl << 2));
				tcph->check = 0;
				tcph->check = csum_tcpudp_magic((iph->saddr), (iph->daddr), len, IPPROTO_TCP, csum_partial((char *)tcph, len, 0));
				break;
			case IPPROTO_UDP:
				udph = (struct udphdr *) (iph + (iph->ihl << 2));
				udph->check = 0;
				udph->check = csum_tcpudp_magic((iph->saddr), (iph->daddr), len, IPPROTO_UDP, 0);
				break;
			default:
				return NF_DROP;

		}
       	ip_send_check (iph);
		skb->ip_summed = CHECKSUM_NONE;
		return XT_CONTINUE;
	}
	return NF_DROP;
}

static unsigned int
ipdst_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *iph;
	const struct ipt_IPADDR_info *info = par->targinfo;
	struct udphdr *udph;
	struct tcphdr *tcph;
	__u32 len;
	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;
	if (skb_linearize(skb)) 
		return NF_DROP;

	iph = ip_hdr(skb);
	if (iph && iph->protocol)
	{
		iph->daddr = info->ipaddr.ip;
	        /* Calculation of IP header checksum */
	        iph->check = 0;
		len = (skb->len - (iph->ihl << 2));
		switch (iph->protocol)
		{
			case IPPROTO_TCP:
				tcph = (struct tcphdr *) (iph + (iph->ihl << 2));
				tcph->check = 0;
				tcph->check = csum_tcpudp_magic((iph->saddr), (iph->daddr), len, IPPROTO_TCP, csum_partial((char *)tcph, len, 0));
				break;
			case IPPROTO_UDP:
				udph = (struct udphdr *) (iph + (iph->ihl << 2));
				udph->check = 0;
				udph->check = csum_tcpudp_magic((iph->saddr), (iph->daddr), len, IPPROTO_UDP, 0);
				break;
			default:
				return NF_DROP;

		}
        	ip_send_check (iph);
		skb->ip_summed = CHECKSUM_NONE;
		return XT_CONTINUE;
	}
	return NF_DROP;
}

static int twin_tg_check(const struct xt_tgchk_param *par)
{
	return 0;
}

static struct xt_target hl_tg_reg[] __read_mostly = {
	{
		.name       = "IPSRC",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = ipsrc_tg,
		.targetsize = sizeof(struct ipt_IPADDR_info),
		.table      = "mangle",
		.checkentry = twin_tg_check,
		.me         = THIS_MODULE,
	},
	{
		.name       = "IPDST",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = ipdst_tg,
		.targetsize = sizeof(struct ipt_IPADDR_info),
		.table      = "mangle",
		.checkentry = twin_tg_check,
		.me         = THIS_MODULE,
	},
	{
		.name       = "IP6SPOOF",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = ip6spoof_tg,
		.targetsize = sizeof(struct ipt_IPADDR_info),
		.table      = "mangle",
		.checkentry = twin_tg_check,
		.me         = THIS_MODULE,
	},
};

static int __init hl_tg_init(void)
{
	return xt_register_targets(hl_tg_reg, ARRAY_SIZE(hl_tg_reg));
}

static void __exit hl_tg_exit(void)
{
	xt_unregister_targets(hl_tg_reg, ARRAY_SIZE(hl_tg_reg));
}

module_init(hl_tg_init);
module_exit(hl_tg_exit);
MODULE_ALIAS("ipt_IPADDR");
