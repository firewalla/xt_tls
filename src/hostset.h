/* 
 * Structures and functions for working with host name sets.
 * Host sets are implemented as simple binary trees of the host_set_elem
 */

#ifndef _HOSTSET_H
#define _HOSTSET_H

#include <linux/rbtree.h>
#include "xt_tls.h"

#ifndef CONFIG_PROC_FS
#error "XT_TLS requires proc filesystem support enabled in the kernel"
#endif

enum host_protocol {
    NONE,
    TCP,
    UDP
};

struct port_desc {
    enum host_protocol protocol;
    unsigned short start;
    unsigned short end;
    struct port_desc *next;
};

// Host set element holding a single host name
struct host_set_elem {
    struct rb_node rbnode;
    __u64 hit_count;
    struct port_desc *ports;   // a linked list of matching port range description. If set to NULL, this entry will match any port.
    bool match_all_ports;
    bool suffix_matching;
    char name[]; //the host name (reversed)
};//host_set_elem


// Host set itself
struct host_set {
    __u32 refcount; // reference count: increased by 1 with each rule using this set
    char name[MAX_HOSTSET_NAME_LEN + 1];  //the set name (stringz)
    struct rb_root hosts;
    struct proc_dir_entry *proc_file;
    loff_t filesize;
};//host_set


// Initialize a host set
int hs_init(struct host_set *hs, const char *name);
// Increment the usage count for the host set
static inline void hs_hold(struct host_set *hs) { hs->refcount++; }
// Free a host set entry (taking into account its refcount)
void hs_free(struct host_set *hs);
// Free a host set entry (unconditionally)
void hs_destroy(struct host_set *hs);
// Check if this host set entry is free (unused)
static inline bool hs_is_free(struct host_set *hs) { return hs->refcount == 0; }
// Zeroize a host set entry (mark it unused)
static inline void hs_zeroize(struct host_set *hs) { hs->refcount = 0; }
// Lookup the host set for the specifed host name
bool hs_lookup(struct host_set *hs, const char *hostname, enum host_protocol protocol,
               unsigned short port, int record_hit);


#endif // _HOSTSET_H