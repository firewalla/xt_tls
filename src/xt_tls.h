#ifndef _XT_TLS_TARGET_H
#define _XT_TLS_TARGET_H

#include <linux/types.h>

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "[%s]:%s: " fmt, KBUILD_MODNAME, __func__


enum {
	O_TLS_HOST    = 0,
	O_TLS_HOSTSET = 1,
	O_TLS_LOG     = 2
};


#define XT_TLS_OP_HOST      0x1 << O_TLS_HOST
#define XT_TLS_OP_HOSTSET   0x1 << O_TLS_HOSTSET
#define XT_TLS_OP_LOG       0x1 << O_TLS_LOG

#define MAX_HOSTNAME_LEN 255
#define MAX_HOSTSET_NAME_LEN 63

#define MAX_PACKET_BUF_SIZE 3000
#define MAX_DOMAIN_SIZE 255
#define MAX_URI_SIZE 1024
// Entries per shard. Kept small on purpose: it bounds the lookup scan, which runs
// while the shard lock is held, so it is the main knob on lock hold time.
// Total capacity is PAYLOAD_SHARD_COUNT * PAYLOAD_LIST_SIZE - the two trade off
// against each other at constant memory, and more shards is the better trade
// (see the note on PAYLOAD_SHARD_BITS below).
#define PAYLOAD_LIST_SIZE 8
// The reassembly cache for ClientHellos that span several TCP segments is a flat
// array of PAYLOAD_SHARD_COUNT shards, each holding PAYLOAD_LIST_SIZE entries
// guarded by its own lock. A connection is mapped to a shard by a
// direction-symmetric hash of its 4-tuple, so every packet of a flow reaches the
// same shard no matter which CPU handles it.
//
// Within a shard the slot is NOT chosen by hash - entries are matched by full
// 4-tuple, so two connections sharing a shard never mistake each other's data.
// What they do compete for is capacity: inserts rotate round-robin through the
// shard's slots, so an entry survives PAYLOAD_LIST_SIZE further inserts into the
// same shard. With PAYLOAD_SHARD_COUNT shards that is ample - the segments of a
// fragmented ClientHello arrive within one RTT, and it would take thousands of new
// fragmented handshakes per second landing in the same shard to cut that short.
// The DIAG line in get_tls_hostname() reports when it does happen anyway.
//
// This replaces a per-CPU layout: with per-CPU rings the partial ClientHello was
// lost whenever RPS, an ifb reinjection, IP defrag or a CPU-affinity change moved
// a flow's packets to another core, which made the flow slip through unmatched.
// Correctness no longer depends on CPU pinning; pinning is now only a locality
// optimisation (a pinned flow keeps hitting one shard, so its lock stays
// cache-hot on that core and never bounces).
//
// Shard count. Note that the shard is picked by OUR hash of the 4-tuple while the
// CPU is picked by RPS from skb->hash - two unrelated hashes, so any CPU can land
// on any shard and a shard's lock line really does move between cores. What keeps
// that cheap is (a) many shards, so simultaneous hits on the *same* shard are
// rare, and (b) a short hold time, which is why PAYLOAD_LIST_SIZE is small and
// why get_tls_hostname() only holds the lock while it is actually touching the
// cache rather than across the whole parse.
//
// 64 shards x 8 entries = 512 entries, the same total (and the same ~2 MiB) as the
// original nr_cpus * 4 * 32 per-CPU layout on a quad-core box, but with 4x fewer
// shard collisions and a 4x shorter locked scan.
#define PAYLOAD_SHARD_BITS 6
#define PAYLOAD_SHARD_COUNT (1 << PAYLOAD_SHARD_BITS)
#define PAYLOAD_SHARD_MASK (PAYLOAD_SHARD_COUNT - 1)

/* target info */
struct xt_tls_info {
	__u16 op_flags, inversion_flags;
	char host_or_set_name[MAX_HOSTNAME_LEN + 1];
        __s32 hostset_index;
	bool log_msg;
};

#define PROC_FS_MODULE_DIR "xt_tls"
#define PROC_FS_HOSTSET_SUBDIR "hostset"
extern struct proc_dir_entry *proc_fs_hostset_dir;
extern uid_t hostset_uid;
extern gid_t hostset_gid;

#endif /* _XT_TLS_TARGET_H */
