#ifndef __UTILS_H__
#define __UTILS_H__

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>


#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "[%s]:%s: " fmt, KBUILD_MODNAME, __func__


void print_hex(const char *msg, const u8 *buf, int len);

bool match_dot_suffix(const char *hostname, const char *suffix);
bool combo_match(const char* pattern, const char* host);
int create_procfs(char *mod_name);
void cleanup_procfs(char *mod_name);
unsigned int get_max_MTU(void);
void init_max_MTU(void);

/* Portable functions */
static inline uint16_t pntoh16(const void *p)
{
    return (uint16_t)*((const uint8_t *)(p)+0)<<8|
           (uint16_t)*((const uint8_t *)(p)+1)<<0;
}

static inline uint32_t pntoh24(const void *p)
{
    return (uint32_t)*((const uint8_t *)(p)+0)<<16|
           (uint32_t)*((const uint8_t *)(p)+1)<<8|
           (uint32_t)*((const uint8_t *)(p)+2)<<0;
}

static inline uint32_t pntoh32(const void *p) {
	return (uint32_t) * ((const uint8_t *)(p) + 0) << 24 |
	       (uint32_t) * ((const uint8_t *)(p) + 1) << 16 |
	       (uint32_t) * ((const uint8_t *)(p) + 2) << 8 |
	       (uint32_t) * ((const uint8_t *)(p) + 3) << 0;
}
void print_packet_info_and_hostname(const struct sk_buff *skb, const struct xt_action_param *par, char * slogan, char *hostname);

#endif /* __UTILS_H__ */