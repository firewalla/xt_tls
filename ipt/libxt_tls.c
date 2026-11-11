#include <stdlib.h>
#include <xtables.h>
#include <stdio.h>
#include <string.h>

#include "xt_tls.h"
#include "libxt_utils.h"


static void tls_help(void)
{
	tls_help_common("tls", PROC_FS_MODULE_DIR);
}

static const struct xt_option_entry tls_opts[] = {
	{
		.name = "tls-host",
		.id = O_TLS_HOST,
		.type = XTTYPE_STRING,
		.size = MAX_HOSTNAME_LEN,
		.flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(struct xt_tls_info, host_or_set_name),
	},
	{
		.name = "tls-hostset",
		.id = O_TLS_HOSTSET,
		.type = XTTYPE_STRING,
		.size = MAX_HOSTSET_NAME_LEN,
		.flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(struct xt_tls_info, host_or_set_name),
	},
	{
		.name = "log-tls",
		.id = O_TLS_LOG,
		.type = XTTYPE_NONE,
	},
	XTOPT_TABLEEND,
};

static struct xtables_match tls_match = {
	.family		= NFPROTO_UNSPEC,
	.name		= "tls",
	.version	= XTABLES_VERSION,
	.revision	= 1,
	.size		= XT_ALIGN(sizeof(struct xt_tls_info)),
	.userspacesize	= offsetof(struct xt_tls_info, hostset_index),
	.help		= tls_help,
	.print		= tls_print,
	.save		= tls_save,
	.x6_parse	= tls_parse,
	.x6_fcheck	= tls_check,
	.x6_options	= tls_opts,
};

void __attribute__((constructor)) libxt_tls_init(void)
{
	xtables_register_match(&tls_match);
}
