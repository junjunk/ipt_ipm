/* Shared library add-on to iptables for IPSRC target
 * (C) 2017 by Vadim Fedorenko <vadimjunk@gmail.com>
 *
 * This program is distributed under the terms of GNU GPL
 */
#include <stdio.h>
#include <xtables.h>
#include "../kernel/ipt_IPADDR.h"

static const struct xt_option_entry IPADDR_opts[] = {
	{.name = "ipaddr-set", .type = XTTYPE_HOST, .id = 1,
	 .excl = 0, .flags = XTOPT_PUT, XTOPT_POINTER(struct ipt_IPADDR_info, ipaddr)},
	XTOPT_TABLEEND,
};

static void IPADDR_help(void)
{
	printf("IPSRC target options\n"
		"  --ipaddr-set value		Set IP address to <value IPv4>\n");
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
	const struct ipt_IPADDR_info *info = 
		(struct ipt_IPADDR_info *) target->data;
	printf(" --ipaddr-set %u", info->ipaddr.ip);
}

static void IPADDR_print(const void *ip, const struct xt_entry_target *target,
                      int numeric)
{
	const struct ipt_IPADDR_info *info =
		(struct ipt_IPADDR_info *) target->data;
	printf(" IP address set to %u", info->ipaddr.ip);
}

static struct xtables_target IPSRC_tg_reg = {
	.name		= "IPSRC",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
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
	xtables_register_target(&IPSRC_tg_reg);
}
