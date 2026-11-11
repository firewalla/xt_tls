#include <stdlib.h>
#include <xtables.h>
#include <stdio.h>
#include <string.h>

#include "xt_tls.h"
#include "libxt_utils.h"


void tls_help_common(char *module_name, char *proc_dir)
{
    printf("%s match options:\n", module_name);
	printf(
		"  [!] --log-tls\n"
		"  [!] --tls-host hostname\n"
		"  [!] --tls-hostset hostset-name\n"
		"  --tls-host and --tls-hostset are mutually exclusive\n"
		"  The content of the hostset <HS> is accessible through "
		"/proc/net/%s/"PROC_FS_HOSTSET_SUBDIR"/<HS>\n",
        proc_dir
	);
}


void tls_parse(struct xt_option_call *cb)
{
	struct xt_tls_info *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
		case O_TLS_HOST:
			info->op_flags |= XT_TLS_OP_HOST;
			if (cb->invert)
				info->inversion_flags |= XT_TLS_OP_HOST;
			break;
		case O_TLS_HOSTSET:
			info->op_flags |= XT_TLS_OP_HOSTSET;
			if (cb->invert)
				info->inversion_flags |= XT_TLS_OP_HOSTSET;
			break;
		case O_TLS_LOG:
			info->log_msg = true;
			break;
		default:
			break;
	}
}

void tls_check(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0)
		xtables_error(PARAMETER_PROBLEM, "TLS: no tls option specified");
	if ((cb->xflags & O_TLS_HOST) && (cb->xflags & O_TLS_HOSTSET))
		xtables_error(PARAMETER_PROBLEM, 
			"TLS: --tls-host and --tls-hostset options can't be specified together");
}

void tls_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_tls_info *info = (const struct xt_tls_info *)match->data;

	printf(" TLS match");
	if (info->op_flags & XT_TLS_OP_HOST) {
	    bool invert = info->inversion_flags & XT_TLS_OP_HOST;
	    printf(" %s host %s", invert ? "!":"", info->host_or_set_name);
	}//if
	
	if (info->op_flags & XT_TLS_OP_HOSTSET) {
	    bool invert = info->inversion_flags & XT_TLS_OP_HOSTSET;
	    printf(" %s hostset %s", invert ? "!":"", info->host_or_set_name);
	}//if

	if (info->log_msg) {
		printf(" log-tls");
	}
}

void tls_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_tls_info *info = (const struct xt_tls_info *)match->data;

	if (info->op_flags & XT_TLS_OP_HOST) {
	    bool invert = info->inversion_flags & XT_TLS_OP_HOST;
	    printf(" %s --tls-host %s", invert ? "!":"", info->host_or_set_name);
	}//if

	if (info->op_flags & XT_TLS_OP_HOSTSET) {
	    bool invert = info->inversion_flags & XT_TLS_OP_HOSTSET;
	    printf(" %s --tls-hostset %s", invert ? "!":"", info->host_or_set_name);
	}//if

	if (info->log_msg) {
		printf(" --log-tls");
	}
}