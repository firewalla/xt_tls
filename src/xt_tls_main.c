#define pr_fmt(fmt) "[" KBUILD_MODNAME "]: " fmt
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/string.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/cache.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/spinlock.h>
#include <asm/errno.h>

#include "compat.h"
#include "xt_tls.h"
#include "hostset.h"
#include "utils.h"

// The maximum number of host sets
static int max_host_sets = 100;


// uid/gid for hostset file
uid_t hostset_uid = 1000;
gid_t hostset_gid = 1000;

module_param(max_host_sets, int, S_IRUGO);
MODULE_PARM_DESC(max_host_sets, "host set table capacity (default 100)");

module_param(hostset_uid, int, S_IRUGO);
MODULE_PARM_DESC(hostset_uid, "uid for hostset file (default 1000)");

module_param(hostset_gid, int, S_IRUGO);
MODULE_PARM_DESC(hostset_gid, "gid for hostset file (default 1000)");

// The table of the host sets we use
static struct host_set **host_set_table;



struct payload {
	// ---- HOT: everything read while scanning a shard, in 57 bytes so that one
	// cacheline answers a non-matching entry. Field order matters here: these used
	// to straddle the 3 KB data[] buffer, so every scanned entry cost two cacheline
	// touches ~3.3 KB apart instead of one. With PAYLOAD_LIST_SIZE entries scanned
	// per packet that was the single largest cost in this function - bigger than
	// the shard lock. Keep data[] last and do not interleave anything into here.
	//
	// Connection key: source/dest IP (IPv4 stored in the first 4 bytes) + TCP ports + seq
	u8 saddr[16];
	u8 daddr[16];
	u16 sport;
	u16 dport;
	u32 seq;
	// Total ClientHello length being assembled. 0 means "slot never used", which is
	// the first thing the scan tests.
	size_t tot_len;
	bool clienthello_complete;

	// ---- COLD: only touched once an entry actually matches a packet.
	size_t cur_len;
	// seq of the packet that completed SNI parsing (for multi-rule record_hit correctness)
	u32 completing_seq;
	// Parsed SNI/host
	char hostname[MAX_DOMAIN_SIZE + 1];
	// TCP payload buffer
	char data[MAX_PACKET_BUF_SIZE];
};

// A shard's entries, used as a ring: inserts rotate through the slots in index
// order and overwrite whatever is there. An entry therefore survives
// PAYLOAD_LIST_SIZE further inserts into its own shard, which with
// PAYLOAD_SHARD_COUNT shards is far longer than the RTT a fragmented ClientHello
// needs. No per-entry timestamp or scan for a "best" victim: the shard is full
// within moments of module load and stays that way, so any such scheme would only
// ever pay off during warm-up.
struct payload_list {
	struct payload *list[PAYLOAD_LIST_SIZE];
	// Next slot to overwrite.
	int next;
	// High-water mark of slots ever written. Only ever grows, and because `next`
	// starts at 0 the written slots are exactly [0, used). Lets the lookup skip a
	// shard that has never cached anything without dereferencing any entry, and
	// lets get_tls_hostname() decide whether the lock is worth taking at all.
	int used;
};

// Take the next slot in the ring. Reports in *evicted whether it was still holding
// a reassembly in progress, which is the only case that loses data.
static int payload_next_slot(struct payload_list *plist, bool *evicted)
{
	struct payload *p;
	int slot = plist->next;

	plist->next = (slot + 1) % PAYLOAD_LIST_SIZE;
	// WRITE_ONCE because the fast path in get_tls_hostname() reads ->used without
	// the lock to decide whether it is worth taking at all.
	if (plist->used < PAYLOAD_LIST_SIZE)
		WRITE_ONCE(plist->used, plist->used + 1);

	p = plist->list[slot];
	*evicted = p->tot_len != 0 && p->cur_len != 0 && !p->clienthello_complete;
	return slot;
}

// One shard of the reassembly cache: an independent entry set plus the lock that
// guards it. Cacheline-aligned so that two shards worked on by two CPUs never
// share a line (false sharing would reintroduce the bouncing we are avoiding).
struct payload_shard {
	spinlock_t lock;
	struct payload_list list;
} ____cacheline_aligned_in_smp;

static DEFINE_PER_CPU(char[MAX_PACKET_BUF_SIZE], payload_buf);
// Statically allocated: guarantees the alignment above and removes an allocation
// failure path for the array itself (the payload entries are still allocated in
// init_payload_shards()).
static struct payload_shard payload_shards[PAYLOAD_SHARD_COUNT];
static bool payload_cache_ready;
// Randomised so a remote peer cannot deliberately steer many flows into one
// shard and evict other connections' in-flight ClientHellos.
static u32 payload_hash_seed __read_mostly;

// Map a connection to its shard. The key is direction-symmetric: swapping
// (saddr,sport) with (daddr,dport) yields the same value, because both XOR and
// addition are commutative. So the request and the reply of one connection land
// in the same shard, and - crucially - so does every segment of one direction
// regardless of which CPU picks it up.
static inline struct payload_shard *payload_shard_for(const u8 *saddr, const u8 *daddr,
                                                      u16 sport, u16 dport)
{
	u32 ha = jhash(saddr, 16, sport);
	u32 hb = jhash(daddr, 16, dport);
	u32 h = jhash_2words(ha ^ hb, ha + hb, payload_hash_seed);

	return &payload_shards[h & PAYLOAD_SHARD_MASK];
}

static inline u32 payload_shard_index(const struct payload_shard *shard)
{
	return (u32)(shard - payload_shards);
}

static char *http_methods[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};

static int get_http_hostname(char *data, int data_len, char *dest) {
	char uri[MAX_URI_SIZE + 1];
	int uri_len;
	int i;
	char *tail = data + data_len;
	char *p;
	bool match_method = false;
	int version_len;
	char *prefix = "http://";
	int prefix_len = strlen(prefix);

	dest[0] = '\0';

	// Skip if packet is too short
	if (data_len < 20) {
		return EPROTO;
	}

	for (i = 0; i < sizeof(http_methods) / sizeof(http_methods[0]); i++) {
		int len = strlen(http_methods[i]);
		if (strncmp(data, http_methods[i], len) == 0) {
			data += len;
			match_method = true;
		}
	}

	if (!match_method) {
		return EPROTO;
	}

	// verify single space after method
	if (data[0] != ' ') {
		return EPROTO;
	}
	data += 1;

	// extract uri
	p = strnchr(data, tail - data, ' ');
	if (p == NULL) {
		return EPROTO;
	}

	uri_len = p - data;
	if (uri_len > MAX_URI_SIZE) {
		return EPROTO;
	}

	strncpy(uri, data, uri_len);
	uri[uri_len] = '\0';
	data += uri_len + 1;


	// match "HTTP/1.1" or "HTTP/1.0"
	version_len = 10;
	if (tail - data <= version_len) {
		return EPROTO;
	}
	if (strncmp(data, "HTTP/1.1\r\n", version_len) != 0 && strncmp(data, "HTTP/1.0\r\n", version_len) != 0) {
		return EPROTO;
	}
	data += version_len;

	// for proxy http request, we can get domain info from absolute uri.
	if (uri_len >= prefix_len && strncmp(uri, prefix, prefix_len) == 0) {
		char *domain_start = uri + prefix_len;
		char *s = strnchr(domain_start, uri_len - prefix_len, '/');
		if (s != NULL) {
			int domain_len = s - domain_start;
			int new_uri_len = uri_len - (s - uri);
			if (domain_len > MAX_DOMAIN_SIZE) {
				return EPROTO;
			}
			memcpy(uri, s, new_uri_len);
			strncpy(dest, domain_start, domain_len);
			uri[new_uri_len] = '\0'; 
			dest[domain_len] = '\0';
		} else {
			return EPROTO;
		}
	}

	// verify uri starts with "/" or is "*";
	if (uri[0] != '/' && !(uri[0] == '*' && strlen(uri) == 1)) {
		return EPROTO;
	}
 
	// look for "Host" http headers to get domain name
	if (dest[0] == '\0') {
		// iterate headers and find host header
		while (data < tail) {
			char *host_header = "Host: ";
			int host_header_len = strlen(host_header);
			p = strnchr(data, tail - data, '\r');
			if (p == NULL) {
				// no end of line
				return EPROTO;
			}
			if (p + 1 >= tail || p[1] != '\n') {
				// not \r\n
				return EPROTO;
			}
			if (p == data) {
				// end of headers
				return EPROTO;
			}
			if (data + host_header_len < p && strncmp(data, host_header, host_header_len) == 0) {
				int domain_len = p - data - host_header_len;
				if (domain_len > MAX_DOMAIN_SIZE) {
					return EPROTO;
				}
				strncpy(dest, data + host_header_len, domain_len);
				dest[domain_len] = '\0';
				break;
			}
			data = p + 2;
		}
	} else {
		pr_debug("Domain already parsed in uri\n");
	}

	// strip port from domain
	p = strchr(dest, ':');
	if (p != NULL) {
		*p = '\0';
	}

	pr_debug("Domain: %s\n", dest);
	pr_debug("URI: %s\n", uri);

	return 0;
}

static struct payload* find_or_merge_cached_payload(struct tcphdr *th, const u8 *saddr, const u8 *daddr, char *data, size_t data_len, struct payload_list *plist) {
	struct payload **pp = plist->list;
	size_t copy_len;
	int idx;

	u32 seq = ntohl(th->seq);

	// Nothing cached in this shard yet - the common case for a shard that has
	// never seen a fragmented ClientHello. Cheap early-out before the scan below
	// starts dereferencing entry pointers.
	if (plist->used == 0)
		return NULL;

	for (idx = 0; idx < plist->used; idx++) {
		struct payload *p = pp[idx];

		// Defensive: a pristine slot is all zeros and cannot describe a real
		// connection. Should not be reachable given the [0, used) invariant.
		if (p->tot_len == 0)
			continue;
		// Match the whole connection: source/dest IP + ports. Ports alone can
		// collide when different flows reuse the same ephemeral port and land
		// in the same shard, causing cross-connection mis-merges.
		if (p->sport == ntohs(th->source) && p->dport == ntohs(th->dest) &&
		    memcmp(p->saddr, saddr, 16) == 0 && memcmp(p->daddr, daddr, 16) == 0) {
			// Wrap-safe forward distance of this packet from the cached
			// start seq. A stale entry left over from a previous connection
			// that happens to reuse the same ports has an unrelated (random)
			// seq, so off lands far outside [0, tot_len] and is rejected.
			// Using only the upper bound (seq <= p->seq + p->tot_len) matched
			// ~half of all unrelated seqs and let stale entries shadow new
			// connections, dropping their fragments.
			u32 off = seq - p->seq;
			if (p->seq == seq)
				return p;
			if (off <= p->tot_len) {
				if (off == p->cur_len && p->cur_len < p->tot_len) { // merge data into cached payload
					copy_len = data_len > MAX_PACKET_BUF_SIZE - p->cur_len ? MAX_PACKET_BUF_SIZE - p->cur_len : data_len;
					memcpy(p->data + p->cur_len, data, copy_len);
					p->cur_len += copy_len;
				}
				return p;
			}
		}
	}
	return NULL;
}

/*
 * Searches through skb->data and looks for a
 * client or server handshake. A client
 * handshake is preferred as the SNI
 * field tells us what domain the client
 * wants to connect to.
 */
static int get_tls_hostname(const struct sk_buff* skb, const u8 *saddr, const u8 *daddr, char* dest,
                            unsigned short* port, unsigned int thoff, int *record_hit) {
	char *data;
	size_t data_len;
	// struct ethhdr _eth, *eth;
	u_int16_t tls_header_len;
	u_int8_t handshake_protocol;
	int rc;
	int idx;
	struct tcphdr _tcp_header_buffer;
	struct tcphdr* tcp_header;
	unsigned int payload_len;
	struct payload *cached_payload = NULL;
	// Shard this connection belongs to, and its entry set. Both stay NULL when the
	// cache is unavailable. Resolving the shard does NOT take its lock - see the
	// locking note further down.
	struct payload_shard *shard = NULL;
	struct payload_list *plist = NULL;
	bool shard_locked = false;
	bool bh_disabled = false;
	int ret = EPROTO;
#ifdef XT_TLS_DEBUG
	// The flow hash RPS would use to steer this packet, for comparing against the
	// shard we pick. Debug builds only: skb_get_hash() can trigger a full flow
	// dissection when skb->hash is not already cached, and paying that on every
	// packet just to feed a log line is not worth it.
	u32 flow_hash;
#endif

	pr_debug("thoff=%u, skb->len=%u\n", thoff, skb->len);

	tcp_header = skb_header_pointer(skb, thoff, sizeof(struct tcphdr),
	                        &_tcp_header_buffer);
	if (tcp_header == NULL) {
		pr_warn("Failed to get TCP header at offset %u\n", thoff);
		return EPROTO;
	}

#ifdef XT_TLS_DEBUG
	// Cast away const: skb_get_hash() may lazily compute and cache skb->hash. The
	// computation is idempotent and matches what get_rps_cpu() sees.
	flow_hash = skb_get_hash((struct sk_buff *)skb);
#endif

	pr_debug("Got TCP header, source port: %u, dest port: %u\n", ntohs(tcp_header->source), ntohs(tcp_header->dest));

	payload_len = skb->len - thoff - tcp_header->doff * 4;
	if ((int)payload_len < 0) {
		return EPROTO;
	}

	pr_debug("TCP header length: %u, payload length: %u\n",
	         tcp_header->doff * 4, payload_len);

#ifdef XT_TLS_DEBUG	
	printk("[xt_tls] tcp_header=%px\n", tcp_header);
	printk("[xt_tls] tcp_header[]: %60ph\n", tcp_header);
	printk("[xt_tls] tcp_header->doff=%u\n", tcp_header->doff);
#endif
	data_len = payload_len;
	// Normally, the tls ClientHello message is in 200-600 bytes range. So we ignore packet larger than 1536 to save stack space.
	if (payload_len > MAX_PACKET_BUF_SIZE) {
		return EPROTO;
	}

	// ---- Locking, in one place -------------------------------------------------
	//
	// Softirqs go off for the rest of the function, but the shard lock is NOT taken
	// yet. They protect different things and conflating them is what made the
	// critical section far larger than it needed to be:
	//
	//  * local_bh_disable() covers `data` possibly pointing into the per-CPU
	//    payload_buf below. Without it a rule in OUTPUT runs in process context and
	//    could migrate cores mid-parse, leaving `data` on another CPU's buffer. It
	//    is a per-CPU preempt_count increment: no atomic, no shared cacheline.
	//    It also means every shard-lock acquisition sits in a bh-disabled region,
	//    so the lock itself can be a plain spin_lock() rather than spin_lock_bh().
	//
	//  * spin_lock(&shard->lock) is taken lazily, only where the cache is really
	//    touched, and only stays held past that point when `data` ends up pointing
	//    *into* a cache entry (the fragmented-ClientHello path, which is rare).
	//    Consequences per shape of traffic:
	//      - complete ClientHello in one segment:  lock never taken at all
	//      - non-TLS packet, shard never used:     lock never taken (->used == 0)
	//      - non-TLS packet, shard in use:         one short locked lookup
	//      - continuation of a fragmented hello:   held across the parse (rare)
	//
	// This matters because the shard is chosen by our 4-tuple hash while the CPU is
	// chosen by RPS from skb->hash - unrelated hashes, so shard locks do get
	// touched from several cores. Keeping the hold time to a bounded scan of
	// PAYLOAD_LIST_SIZE entries is what makes that cheap.
	local_bh_disable();
	bh_disabled = true;

	if (payload_cache_ready) {
		shard = payload_shard_for(saddr, daddr, ntohs(tcp_header->source),
		                          ntohs(tcp_header->dest));
		plist = &shard->list;
	}

	// ...and check if we really have the entire packet
	if (skb_is_nonlinear(skb)) {
	        // if not - copy the missing portion from wherever it is
#ifdef XT_TLS_DEBUG
		printk("[xt_tls] Not all payload available right now - try to gather it\n");
#endif
		data = this_cpu_ptr(payload_buf);
		if (skb_copy_bits(skb, thoff + tcp_header->doff * 4, data, payload_len)) {
			goto out;
		}//if
	} else {
		data = (char *)tcp_header + (tcp_header->doff * 4);
	}

#ifdef XT_TLS_DEBUG
	printk("[xt_tls] data=%px\n", data);
	printk("[xt_tls] data[]: %64ph\n", data);
	printk("[xt_tls] Content-type=0x%X\n", (unsigned char)data[0]);
#endif

	// detect whether it's http request
	rc = get_http_hostname(data, data_len, dest);
	if (rc == 0) {
		*port = htons(tcp_header->dest);
		ret = 0;
		goto out;
	}

	// If this isn't an TLS handshake, abort
	if (data[0] != 0x16 || data_len < 5) {
		struct payload *p = NULL;
#ifdef XT_TLS_DEBUG
		printk("[xt_tls] Not TLS handshaking\n");
#endif
		// ->used only ever grows, and an entry of ours can only exist if one of
		// our own earlier packets inserted it - which already bumped ->used. So a
		// lockless zero here means "nothing of ours can be in this shard" and the
		// lock is not worth taking. A shard that has never seen a fragmented
		// ClientHello therefore costs no locking at all on this path.
		if (plist && READ_ONCE(plist->used)) {
			// Lock stays held from here on if we find something: `data` will be
			// repointed into the entry below, and a successful parse writes the
			// hostname back into it.
			spin_lock(&shard->lock);
			shard_locked = true;
			p = find_or_merge_cached_payload(tcp_header, saddr, daddr, data, data_len, plist);
		}
		if (p) {
#ifdef XT_TLS_DEBUG
			printk("[xt_tls] merged with cached payload, sport=%u, seq=%u, cur_len=%lu, tot_len=%lu", ntohs(tcp_header->source), ntohl(tcp_header->seq), p->cur_len, p->tot_len);
#endif
			// DIAG: continuation fragment matched a still-assembling entry.
			// Absence of this line for a flow whose insert we logged now points
			// at eviction (see "evicting incomplete partial") only - a CPU
			// switch can no longer cause it, since the shard is derived from the
			// 4-tuple rather than from smp_processor_id().
			if (!p->clienthello_complete)
				pr_debug("diag cache-hit(assembling): cpu=%d shard=%u sport=%u dport=%u seq=%u cur_len=%zu tot_len=%zu\n",
					smp_processor_id(), payload_shard_index(shard),
					ntohs(tcp_header->source), ntohs(tcp_header->dest), ntohl(tcp_header->seq),
					p->cur_len, p->tot_len);
			data = p->data;
			data_len = p->cur_len;
			cached_payload = p;
			if (p->clienthello_complete && p->hostname[0] != '\0') {
				strncpy(dest, p->hostname, MAX_DOMAIN_SIZE);
				dest[MAX_DOMAIN_SIZE] = '\0';
				*port = htons(tcp_header->dest);
				// Same packet evaluated by multiple iptables rules: restore record_hit
				// so each matching rule can count the hit exactly once per connection.
				if (ntohl(tcp_header->seq) == p->completing_seq)
					*record_hit = 1;
				ret = 0;
				goto out;
			}
		} else {
			// DIAG: a continuation fragment arrived but found no matching entry.
			// The shard is now a pure function of the 4-tuple, so cpu= differing
			// between the insert and this line is expected and harmless. A miss
			// here means either the entry was evicted (look for "evicting
			// incomplete partial" on the same shard) or this really is not a
			// continuation of a cached ClientHello.
			pr_debug("diag cache-miss: cpu=%d shard=%u sport=%u dport=%u seq=%u DEV=%s RX_QUEUE=%u\n",
				smp_processor_id(), shard ? payload_shard_index(shard) : ~0U,
				ntohs(tcp_header->source), ntohs(tcp_header->dest), ntohl(tcp_header->seq),
				skb->dev ? skb->dev->name : "none", skb_get_rx_queue(skb));
			pr_debug("No cached payload found for this packet, cpu=%d, sport=%u, seq=%u DEV=%s RX_QUEUE=%u\n", smp_processor_id(), ntohs(tcp_header->source), ntohl(tcp_header->seq), skb->dev ? skb->dev->name : "none", skb_get_rx_queue(skb));
			goto out;
		}
	}

	tls_header_len = ((unsigned char)data[3] << 8) + (unsigned char)data[4] + 5;
	handshake_protocol = data[5];

	if (tls_header_len > 4) {
		// Check only client hellos for now
		if (handshake_protocol == 0x01) {
			u_int offset, base_offset = 43, extension_offset = 2;
			u_int16_t session_id_len, cipher_len, compression_len, extensions_len;

#ifdef XT_TLS_DEBUG
			printk("[xt_tls] tls_header_len=%u, data_len=%zu, sport=%u, seq=%u\n", tls_header_len, data_len, ntohs(tcp_header->source), ntohl(tcp_header->seq));
#endif

			// If tls header is incomplete in a packet, hold the partial data in the
			// flow's shard; it will be merged with subsequent packets - which reach
			// the same shard whatever CPU handles them - and processed later.
			if (tls_header_len > data_len && tls_header_len <= MAX_PACKET_BUF_SIZE && plist) {
				struct payload **pp = plist->list;
				struct payload *p = NULL;
				bool evicted = false;
				// Already held if we got here through the cached path above;
				// otherwise this is a fresh, single-segment-so-far handshake and
				// this is the first time we touch the shard.
				if (!shard_locked) {
					spin_lock(&shard->lock);
					shard_locked = true;
				}
				if (find_or_merge_cached_payload(tcp_header, saddr, daddr, data, data_len, plist)) { // already cached
#ifdef XT_TLS_DEBUG
					printk("[xt_tls] partial tls header is already in cached payload, cpu=%d, shard=%u, sport=%u, seq=%u, hash:%u, DEV=%s RX_QUEUE=%u", smp_processor_id(), payload_shard_index(shard), ntohs(tcp_header->source), ntohl(tcp_header->seq), flow_hash, skb->dev ? skb->dev->name : "none", skb_get_rx_queue(skb));
#endif
					ret = 0;
					goto out;
				}
#ifdef XT_TLS_DEBUG
				printk("[xt_tls] adding partial tls header to cache, cpu=%d, shard=%u, sport=%u, seq=%u tot_len=%u, hash=%u DEV=%s RX_QUEUE=%u", smp_processor_id(), payload_shard_index(shard), ntohs(tcp_header->source), ntohl(tcp_header->seq), tls_header_len, flow_hash, skb->dev ? skb->dev->name : "none", skb_get_rx_queue(skb));
#endif
				idx = payload_next_slot(plist, &evicted);
				p = pp[idx];

				// DIAG: first fragment of a fragmented ClientHello is being cached.
				pr_debug("diag cache-insert: cpu=%d shard=%u slot=%d sport=%u dport=%u seq=%u tot_len=%u data_len=%zu\n",
					smp_processor_id(), payload_shard_index(shard), idx,
					ntohs(tcp_header->source), ntohs(tcp_header->dest), ntohl(tcp_header->seq),
					tls_header_len, data_len);

				// DIAG: the slot the ring landed on still held a reassembly in
				// progress. This is the only case that loses data - a later
				// continuation fragment of that connection will fail to find its
				// cache - and the signal to raise PAYLOAD_SHARD_BITS or
				// PAYLOAD_LIST_SIZE.
				// Fields are the VICTIM's real identity (p->*), not the new packet.
				if (evicted) {
					pr_debug("diag evicting in-flight partial: cpu=%d shard=%u slot=%d victim sport=%u dport=%u seq=%u cur_len=%zu tot_len=%zu; evicted-by sport=%u seq=%u\n",
						smp_processor_id(), payload_shard_index(shard), idx,
						p->sport, p->dport, p->seq, p->cur_len, p->tot_len,
						ntohs(tcp_header->source), ntohl(tcp_header->seq));
				}

				memset(p, 0, sizeof(struct payload));
				p->sport = ntohs(tcp_header->source);
				p->dport = ntohs(tcp_header->dest);
				memcpy(p->saddr, saddr, 16);
				memcpy(p->daddr, daddr, 16);
				p->seq = ntohl(tcp_header->seq);
				p->tot_len = tls_header_len;
				p->cur_len = data_len;
				p->clienthello_complete = false;
				p->hostname[0] = '\0';
				memcpy(p->data, data, data_len);
				ret = 0;
				goto out;
			}

			if (base_offset + 2 > data_len) {
#ifdef XT_TLS_DEBUG
				printk("[xt_tls] Data length is to small (%d)\n", (int)data_len);
#endif
				goto out;
			}

			// Get the length of the session ID
			session_id_len = data[base_offset];

#ifdef XT_TLS_DEBUG
			printk("[xt_tls] Session ID length: %d\n", session_id_len);
#endif
			if ((session_id_len + base_offset + 2) > tls_header_len) {
#ifdef XT_TLS_DEBUG
				printk("[xt_tls] TLS header length is smaller than session_id_len + base_offset +2 (%d > %d)\n", (session_id_len + base_offset + 2), tls_header_len);
#endif
				goto out;
			}

			// Get the length of the ciphers
			memcpy(&cipher_len, &data[base_offset + session_id_len + 1], 2);
			cipher_len = ntohs(cipher_len);
			offset = base_offset + session_id_len + cipher_len + 2;
#ifdef XT_TLS_DEBUG
			printk("[xt_tls] Cipher len: %d\n", cipher_len);
			printk("[xt_tls] Offset (1): %d\n", offset);
#endif
			if (offset > tls_header_len) {
#ifdef XT_TLS_DEBUG
				printk("[xt_tls] TLS header length is smaller than offset (%d > %d)\n", offset, tls_header_len);
#endif
				goto out;
			}

			// Get the length of the compression types
			compression_len = data[offset + 1];
			offset += compression_len + 2;
#ifdef XT_TLS_DEBUG
			printk("[xt_tls] Compression length: %d\n", compression_len);
			printk("[xt_tls] Offset (2): %d\n", offset);
#endif
			if (offset > tls_header_len) {
#ifdef XT_TLS_DEBUG
				printk("[xt_tls] TLS header length is smaller than offset w/compression (%d > %d)\n", offset, tls_header_len);
#endif
				goto out;
			}

			// Get the length of all the extensions
			memcpy(&extensions_len, &data[offset], 2);
			extensions_len = ntohs(extensions_len);
#ifdef XT_TLS_DEBUG
			printk("[xt_tls] Extensions length: %d\n", extensions_len);
#endif

			if ((extensions_len + offset) > tls_header_len) {
#ifdef XT_TLS_DEBUG
				printk("[xt_tls] TLS header length is smaller than offset w/extensions (%d > %d)\n", (extensions_len + offset), tls_header_len);
#endif
				goto out;
			}

			// Loop through all the extensions to find the SNI extension
			while (extension_offset < extensions_len)
			{
				u_int16_t extension_id, extension_len;

				memcpy(&extension_id, &data[offset + extension_offset], 2);
				extension_offset += 2;

				memcpy(&extension_len, &data[offset + extension_offset], 2);
				extension_offset += 2;

				extension_id = ntohs(extension_id), extension_len = ntohs(extension_len);

#ifdef XT_TLS_DEBUG
				printk("[xt_tls] Extension ID: %d\n", extension_id);
				printk("[xt_tls] Extension length: %d\n", extension_len);
#endif

				if (extension_id == 0) {
					u_int16_t name_length, name_type;

					// We don't need the server name list length, so skip that
					extension_offset += 2;
					// We don't really need name_type at the moment
					// as there's only one type in the RFC-spec.
					// However I'm leaving it in here for
					// debugging purposes.
					name_type = data[offset + extension_offset];
					extension_offset += 1;

					memcpy(&name_length, &data[offset + extension_offset], 2);
					name_length = ntohs(name_length);
					if (name_length > MAX_DOMAIN_SIZE) {
						goto out;
					}
					extension_offset += 2;

#ifdef XT_TLS_DEBUG
					printk("[xt_tls] Name type: %d\n", name_type);
					printk("[xt_tls] Name length: %d\n", name_length);
#endif
					// Allocate an extra byte for the null-terminator
					strncpy(dest, &data[offset + extension_offset], name_length);
					// Make sure the string is always null-terminated.
					dest[name_length] = 0;
					// cached_payload is only ever set on the path that took the
					// shard lock and kept it, so this write is protected.
					if (cached_payload) {
						cached_payload->clienthello_complete = true;
						strncpy(cached_payload->hostname, dest, name_length);
						cached_payload->hostname[name_length] = '\0';
						cached_payload->completing_seq = ntohl(tcp_header->seq);
					}
					*record_hit = 1;
					*port = htons(tcp_header->dest);
					ret = 0;
					goto out;
				}

				extension_offset += extension_len;
			}
		}
	}

out:
	// Single exit point. Both flags are false on the early returns above this
	// point, which happen before local_bh_disable() - keeping them explicit rather
	// than unlocking unconditionally means a future "goto out" added too early
	// cannot corrupt preempt_count.
	if (shard_locked)
		spin_unlock(&shard->lock);
	if (bh_disabled)
		local_bh_enable();
	return ret;
}

static bool tls_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	char parsed_host[MAX_DOMAIN_SIZE + 1];
	unsigned short port = 0;

	const struct xt_tls_info *info = par->matchinfo;
	int result;
	
	int pattern_type = (info->op_flags & XT_TLS_OP_HOSTSET) ?
	    XT_TLS_OP_HOSTSET : XT_TLS_OP_HOST;
	bool invert = (pattern_type == XT_TLS_OP_HOSTSET) ?
	    (info->inversion_flags & XT_TLS_OP_HOSTSET) :
	    (info->inversion_flags & XT_TLS_OP_HOST);
	bool match;
	int record_hit = 0;
	u8 saddr[16] = {0}, daddr[16] = {0};

	memset(parsed_host, 0, MAX_DOMAIN_SIZE + 1);

	if (par->match->family == NFPROTO_IPV4) {
		const struct iphdr *iph = ip_hdr(skb);
		memcpy(saddr, &iph->saddr, sizeof(iph->saddr));
		memcpy(daddr, &iph->daddr, sizeof(iph->daddr));
	} else if (par->match->family == NFPROTO_IPV6) {
		const struct ipv6hdr *ip6h = ipv6_hdr(skb);
		memcpy(saddr, &ip6h->saddr, sizeof(ip6h->saddr));
		memcpy(daddr, &ip6h->daddr, sizeof(ip6h->daddr));
	}

	if ((result = get_tls_hostname(skb, saddr, daddr, parsed_host, &port, par->thoff, &record_hit)) != 0)
		return false;

	switch (pattern_type) {
	    case XT_TLS_OP_HOST:
            match = combo_match(info->host_or_set_name, parsed_host);
            break;
	    case XT_TLS_OP_HOSTSET:
            match = hs_lookup(host_set_table[info->hostset_index], parsed_host, TCP, port, record_hit);
            break;
	}//switch

	if (info->log_msg) {
		print_packet_info_and_hostname(skb, par, "FW_TLS", parsed_host);
	}

#ifdef XT_TLS_DEBUG
	printk("[xt_tls] Parsed domain: %s\n", parsed_host);
	printk("[xt_tls] Domain matches: %s, invert: %s\n", match ? "true" : "false", invert ? "true" : "false");
#endif
	if (invert)
		match = !match;


	return match;
}


static int tls_mt_check (const struct xt_mtchk_param *par)
{
	__u16 proto;
	struct xt_tls_info *match_info = par->matchinfo;

	if (par->family == NFPROTO_IPV4) {
		proto = ((const struct ipt_ip *) par->entryinfo)->proto;
	} else if (par->family == NFPROTO_IPV6) {
		proto = ((const struct ip6t_ip6 *) par->entryinfo)->proto;
	} else {
		return -EINVAL;
	}

	if (proto != IPPROTO_TCP) {
		pr_info("Can be used only in combination with -p tcp\n");
		return -EINVAL;
	}
	
	// If the rule contains --tls-hostset, try to find an existing matching
	// hostset table entry or allocate a new one
	if (match_info->op_flags & XT_TLS_OP_HOSTSET) {
	    int i;
	    bool found = false;
	    
	    for (i = 0; i < max_host_sets; i++) {
		found = !hs_is_free(host_set_table[i]) && 
		    strcmp(host_set_table[i]->name, match_info->host_or_set_name) == 0;
		if (found)
		    break;
	    }//for
	    
	    if (found) {
		hs_hold(host_set_table[i]);
	    } else {
		int rc;
		for (i = 0; i < max_host_sets; i++) {
		    found = hs_is_free(host_set_table[i]);
		    if (found)
			break;
		}//for
		if (!found) {
		    pr_err("Cannot add a new hostset: the hostset table is full\n");
		    return -ENOMEM;
		}//if
		rc = hs_init(host_set_table[i], match_info->host_or_set_name);
		if (rc)
		    return rc;
	    }//if
	    
	    match_info->hostset_index = i;
	}//if

	return 0;
}


static void tls_mt_destroy(const struct xt_mtdtor_param *par)
{
	struct xt_tls_info *match_info = par->matchinfo;
#ifdef XT_TLS_DEBUG
	pr_info("tls_mt_destroy: match_info: op_flags=0x%X, hostset_index=%u\n", 
		match_info->op_flags, match_info->hostset_index);
#endif
	if (match_info->op_flags & XT_TLS_OP_HOSTSET) {
	    hs_free(host_set_table[match_info->hostset_index]);
	}//if
}//tls_mt_destroy


static struct xt_match tls_mt_regs[] __read_mostly = {
	{
		.name       = "tls",
		.revision   = 1,
		.family     = NFPROTO_IPV4,
		.checkentry = tls_mt_check,
		.destroy    = tls_mt_destroy,
		.match      = tls_mt,
		.matchsize  = sizeof(struct xt_tls_info),
		.me         = THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name       = "tls",
		.revision   = 1,
		.family     = NFPROTO_IPV6,
		.checkentry = tls_mt_check,
		.destroy    = tls_mt_destroy,
		.match      = tls_mt,
		.matchsize  = sizeof(struct xt_tls_info),
		.me         = THIS_MODULE,
	},
#endif
};

static void destroy_payload_shards(void) {
	int s;
	int i;

	// Close the cache to the match before freeing anything. Both callers run
	// either before xt_register_matches() or after xt_unregister_matches(), so no
	// packet can be inside get_tls_hostname() at this point.
	payload_cache_ready = false;

	for (s = 0; s < PAYLOAD_SHARD_COUNT; s++) {
		struct payload_list *plist = &payload_shards[s].list;
		for (i = 0; i < PAYLOAD_LIST_SIZE; i++) {
			if (plist->list[i]) {
				kfree(plist->list[i]);
				plist->list[i] = NULL;
			}
		}
		plist->next = 0;
		plist->used = 0;
	}
}

static int init_payload_shards(void) {
	int s;
	int i;

	// Keyed hashing: without a random seed a peer could craft connections whose
	// 4-tuples all land in one shard and evict other flows' partial ClientHellos.
	get_random_bytes(&payload_hash_seed, sizeof(payload_hash_seed));

	// Total capacity is PAYLOAD_SHARD_COUNT * PAYLOAD_LIST_SIZE entries, which
	// matches what the previous nr_possible_cpus * 4 * PAYLOAD_LIST_SIZE per-CPU
	// layout allocated on a quad-core box - so no memory regression there.
	for (s = 0; s < PAYLOAD_SHARD_COUNT; s++) {
		struct payload_shard *shard = &payload_shards[s];
		struct payload_list *plist = &shard->list;

		spin_lock_init(&shard->lock);
		for (i = 0; i < PAYLOAD_LIST_SIZE; i++) {
			plist->list[i] = kmalloc(sizeof(struct payload), GFP_KERNEL);
			if (!plist->list[i]) {
				pr_err("Cannot allocate memory for the payload list of shard %d\n", s);
				goto err_free_payload_shards;
			}
			// Zeroed means tot_len == 0, which find_or_merge_cached_payload()
			// reads as "slot never used" and skips.
			memset(plist->list[i], 0, sizeof(struct payload));
		}
	}

	payload_cache_ready = true;
	return 0;
err_free_payload_shards:
	destroy_payload_shards();
	return -ENOMEM;
}


static void destroy_host_set_table(void) {
	int i;
	if (!host_set_table)
		return ;
	for (i = 0; i < max_host_sets; i++) {
		if (host_set_table[i]) {
			hs_destroy(host_set_table[i]);
			kfree(host_set_table[i]);
			host_set_table[i] = NULL;
		}
	}
	kfree(host_set_table);
	host_set_table = NULL;
}

static int init_host_set_table(void) {
	int i;
	host_set_table =
	    kmalloc(sizeof(struct host_set *) * max_host_sets, GFP_NOWAIT);
	if (!host_set_table) {
		pr_err("Cannot allocate memory for the host set table\n");
		return -ENOMEM;
	}  // if

	for (i = 0; i < max_host_sets; i++) {
		host_set_table[i] = kmalloc(sizeof(struct host_set), GFP_NOWAIT);
		if (!host_set_table[i]) {
			pr_err("Cannot allocate memory for the host set %d\n", i);
			goto err_free_resources;
		}
		hs_zeroize(host_set_table[i]);
	}

	return 0;
err_free_resources:
	destroy_host_set_table();
	return -ENOMEM;
}


static int __init tls_mt_init (void)
{
	int rc;

	// cleanup before create
	cleanup_procfs(KBUILD_MODNAME);
	create_procfs(KBUILD_MODNAME);
	rc = init_payload_shards();
	if (rc) {
		pr_err("Cannot initialize the payload reassembly shards\n");
		goto err_cleanup_procfs;
	}

	rc = init_host_set_table();
	if (rc) {
	    pr_err("Cannot allocate memory for the host set table\n");
	    goto err_free_payload_shards;
	}//if

	rc = xt_register_matches(tls_mt_regs, ARRAY_SIZE(tls_mt_regs));
	if (rc) {
		pr_err("Cannot register the TLS match\n");
		goto err_free_host_set_table;
	}

	pr_info("Host set table allocated (%u elements max)\n", max_host_sets);
	
	return 0;

err_free_host_set_table:
	destroy_host_set_table();
err_free_payload_shards:
	destroy_payload_shards();
err_cleanup_procfs:
        cleanup_procfs(KBUILD_MODNAME);
	return rc;
}

static void __exit tls_mt_exit (void)
{
	pr_info("deregistering kernel module...\n");
	xt_unregister_matches(tls_mt_regs, ARRAY_SIZE(tls_mt_regs));	
	destroy_host_set_table();
	cleanup_procfs(KBUILD_MODNAME);
	destroy_payload_shards();
	pr_info("deregistered\n");
}

module_init(tls_mt_init);
module_exit(tls_mt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nils Andreas Svee <nils@stokkdalen.no>");
MODULE_DESCRIPTION("Xtables: TLS (SNI) matching");
MODULE_ALIAS("ipt_tls");
