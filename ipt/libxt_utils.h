#ifndef _LIBXT_UTILS_H_
#define _LIBXT_UTILS_H_



void tls_help_common(char *module_name, char *proc_dir);
void tls_parse(struct xt_option_call *cb);
void tls_check(struct xt_fcheck_call *cb);
void tls_print(const void *ip, const struct xt_entry_match *match, int numeric);
void tls_save(const void *ip, const struct xt_entry_match *match);

#endif /* _LIBXT_UTILS_H_ */