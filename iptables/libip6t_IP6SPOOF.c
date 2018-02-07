/* Shared library add-on to iptables for the IP6SPOOF target
 * (C) 2017 by Vadim Fedorenko <vadimjunk@gmail.com>
 *
 * This program is distributed under the terms of GNU GPL
 */
#include <stdio.h>
#include <xtables.h>
#include "../kernel/ipt_IPADDR.h"

static const struct xt_option_entry IPADDR_opts[] = {
	XTOPT_TABLEEND,
};

static void IPADDR_help(void)
{
	printf("IP6SPOOF target options inserts IPv4 source address"
		" into IPv6 address\n");
}

static void IPADDR_parse(struct xt_option_call *cb)
{
	xtables_option_parse(cb);
}

static void IPADDR_check(struct xt_fcheck_call *cb)
{
}

static void IPADDR_save(const void *ip, const struct xt_entry_target *target)
{
}

static void IPADDR_print(const void *ip, const struct xt_entry_target *target,
                      int numeric)
{
	printf(" IP address spoof is on");
}

static struct xtables_target IP6SPOOF_tg_reg = {
	.name		= "IP6SPOOF",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_IPV6,
	.size		= XT_ALIGN(sizeof(struct ipt_IPADDR_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_IPADDR_info)),
	.help		= IPADDR_help,
	.print		= IPADDR_print,
	.save		= IPADDR_save,
	.x6_parse	= IPADDR_parse,
	.x6_fcheck	= IPADDR_check,
	.x6_options	= IPADDR_opts,
};


void _init(void)
{
	xtables_register_target(&IP6SPOOF_tg_reg);
}
