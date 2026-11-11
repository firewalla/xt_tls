/*
 * Structures and functions for working with host name sets.
 * Host sets are implemented as simple binary trees of the host_set_elem
 */

#include "hostset.h"

#include <asm/errno.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "xt_tls.h"

static DEFINE_RWLOCK(hs_lock);
static char *sm_prefix = "*.";
static size_t sm_prefix_len = 2;

static void hse_free(struct host_set_elem *hse, struct rb_root *root);
static void strrev(char *dst, const char *src, size_t max_len);
static int seq_file_open(struct inode *inode, struct file *file);
static ssize_t proc_write(struct file *file, const char __user *input,
                          size_t size, loff_t *loff);

// Params for displaying a hostset content and calculationg its file size
#define HIT_COUNT_DISPL_WIDTH 12
#define HSE_SIZE_OVERHEAD (HIT_COUNT_DISPL_WIDTH + 2)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define HAVE_PROC_OPS
#endif

#ifdef HAVE_PROC_OPS
static const struct proc_ops proc_fops = {
    .proc_open = seq_file_open,
    .proc_read = seq_read,
    .proc_write = proc_write,
    .proc_release = seq_release,
    .proc_lseek = seq_lseek,
};
#else
static struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .open = seq_file_open,
    .read = seq_read,
    .write = proc_write,
    .release = seq_release,
    .llseek = seq_lseek,
};
#endif

// Initialize a host set
int hs_init(struct host_set *hs, const char *name) {
	kuid_t uid = make_kuid(&init_user_ns, hostset_uid);
	kgid_t gid = make_kgid(&init_user_ns, hostset_gid);

	if (strlen(name) > MAX_HOSTSET_NAME_LEN) return -EINVAL;

	strcpy(hs->name, name);
	hs->refcount = 1;
	hs->hosts = RB_ROOT;
	hs->filesize = 0;

	pr_info(
	    "Creating procfs file for host set /proc/net/xt_tls/hostset/%s\n",
	    name);

	hs->proc_file =
	    proc_create_data(name, 0644, proc_fs_hostset_dir, &proc_fops, hs);
	if (!hs->proc_file) {
		hs->refcount = 0;
		pr_err("Cannot create a procfs file for the host set %s\n",
		       name);
		return -EFAULT;
	}  // if
	proc_set_user(hs->proc_file, uid, gid);

	return 0;
}  // hs_init

// Create a new hostset element in the heap
static struct host_set_elem *hse_create(char *entry, int *err) {
	char *hostname = strsep(&entry, ",");
	size_t len = strlen(hostname);
	struct host_set_elem *hse;
	char *protocol = NULL;
	long start_port;
	long end_port;

	if (len > MAX_HOSTNAME_LEN) len = MAX_HOSTNAME_LEN;

	hse = kmalloc(sizeof(struct host_set_elem) + len + 1, GFP_NOWAIT);
	if (!hse) {
		*err = -ENOMEM;
		return NULL;
	}
	RB_CLEAR_NODE(&hse->rbnode);
	hse->rbnode.rb_left = hse->rbnode.rb_right = NULL;
	hse->hit_count = 0;

	if (entry != NULL) {
		protocol = strsep(&entry, ":");
		if (entry != NULL) {
			char *start_port_str = NULL;
			char *end_port_str = NULL;
			int r;
			start_port_str = strsep(&entry, "-");
			end_port_str = entry;
			r = kstrtol(start_port_str, 10, &start_port);
			if (r != 0) {
				pr_info("error parsing port\n");
				*err = -EINVAL;
				goto ERROR;
			}
			if (end_port_str == NULL) {
				end_port = start_port;
			} else {
				r = kstrtol(end_port_str, 10, &end_port);
				if (r != 0) {
					pr_info("error parsing port\n");
					*err = -EINVAL;
					goto ERROR;
				}
			}
		} else {
			*err = -EINVAL;
			goto ERROR;
		}
	}

	if (protocol == NULL) {
		hse->ports = NULL;
		hse->match_all_ports = true;
	} else {
		struct port_desc *port;
		if (strcmp(protocol, "tcp") != 0 &&
		    strcmp(protocol, "udp") != 0) {
			pr_info("error protocol %s\n", protocol);
			*err = -EINVAL;
			goto ERROR;
		}
		if (start_port < 0 || start_port > 65535 || end_port < 0 ||
		    end_port > 65535 || start_port > end_port) {
			pr_info("invalid port range %ld-%ld\n", start_port,
			        end_port);
			*err = -EINVAL;
			goto ERROR;
		}
		port = kmalloc(sizeof(struct port_desc), GFP_NOWAIT);
		if (port == NULL) {
			*err = -ENOMEM;
			goto ERROR;
		}
		port->start = start_port;
		port->end = end_port;
		if (strcmp(protocol, "tcp") == 0) {
			port->protocol = TCP;
		} else if (strcmp(protocol, "udp") == 0) {
			port->protocol = UDP;
		}
		port->next = NULL;
		hse->ports = port;
		hse->match_all_ports = false;
	}
#ifdef XT_TLS_DEBUG
	{
		char port_info[512] = "";
		if (hse->ports != NULL) {
			snprintf(port_info, 511, " (%d:%hu-%hu)",
			         hse->ports->protocol, hse->ports->start,
			         hse->ports->end);
		}
		pr_info("Entry parsed: %s%s\n", hostname, port_info);
	}
#endif
	if (strncmp(hostname, sm_prefix, sm_prefix_len) == 0) {
		// hse->name only holds the string without "*."
		hse->suffix_matching = true;
		strrev(hse->name, hostname + sm_prefix_len,
		       len - sm_prefix_len);
	} else {
		hse->suffix_matching = false;
		strrev(hse->name, hostname, len);
	}

	return hse;

ERROR:
	kfree(hse);
	return NULL;
}  // hse_create

static bool port_equal(const struct port_desc *a, const struct port_desc *b) {
	if (a->start == b->start && a->end == b->end &&
	    a->protocol == b->protocol) {
		return true;
	} else {
		return false;
	}
}

static void free_ports(struct port_desc *port) {
	struct port_desc *p = port;
	while (p != NULL) {
		struct port_desc *next = p->next;
		kfree(p);
		p = next;
	}
}

static void free_single_hse(struct host_set_elem *hse) {
	if (hse == NULL) {
		return;
	}
	free_ports(hse->ports);
	kfree(hse);
	return;
}

static int cmp_hse(struct host_set_elem *a, struct host_set_elem *b) {
	int cmp = strcmp(a->name, b->name);
	if (cmp != 0) {
		return cmp;
	} else {
		if (!a->suffix_matching && b->suffix_matching) {
			return -1;
		} else if (a->suffix_matching && !b->suffix_matching) {
			return 1;
		} else {
			return 0;
		}
	}
}

// Add an entry to this set
// Example entry format:
// - "www.google.com,tcp:440-443"   match port range
// - "*.google.com,tcp:22"          match single port
// - "www.cnn.com"                  match any protocol and ports
// tcp and udp protocol are parsed but only tcp will take effect.

static int hs_add_entry(struct host_set *hs, char *entry) {
	struct rb_node **link = NULL, *parent = NULL;
	bool already_have = false;
	struct host_set_elem *new_elem;
	struct host_set_elem *found = NULL;
	int err = 0;

	if (strlen(entry) == 0) {
		pr_debug("Empty entry is not allowed\n");
		return -EINVAL;
	}  // if

	new_elem = hse_create(entry, &err);
	if (!new_elem) {
		pr_debug("Cannot create hostset element from entry\n");
		return err;
	}  // if

#ifdef XT_TLS_DEBUG
	pr_info("New hostset elem created at %px:\n", new_elem);
	pr_info("  rbnode: l=%px, r=%px, color=%lu\n", new_elem->rbnode.rb_left,
	        new_elem->rbnode.rb_left, new_elem->rbnode.__rb_parent_color);
	pr_info("  name='%s'\n", new_elem->name);
#endif

	write_lock_bh(&hs_lock);

	link = &hs->hosts.rb_node;

	while (*link) {
		struct host_set_elem *hse =
		    rb_entry(*link, struct host_set_elem, rbnode);
		int cmp = cmp_hse(new_elem, hse);
		parent = *link;
		if (cmp < 0)
			link = &(*link)->rb_left;
		else if (cmp > 0)
			link = &(*link)->rb_right;
		else {
			found = hse;
			already_have = true;
			break;
		}  // if
	}  // while

	if (!already_have) {
		rb_link_node(&new_elem->rbnode, parent, link);
		rb_insert_color(&new_elem->rbnode, &hs->hosts);
		hs->filesize += strlen(new_elem->name) + HSE_SIZE_OVERHEAD;
	}  // if

	if (already_have) {
		pr_debug("Found existing element\n");
		if (new_elem->match_all_ports) {
			found->match_all_ports = true;
		} else {
			struct port_desc *new_port = new_elem->ports;
			const struct port_desc *p = found->ports;
			while (p != NULL) {
				if (port_equal(new_port, p)) {
					kfree(new_port);
					new_port = NULL;
					break;
				}
				p = p->next;
			}
			if (new_port != NULL) {
				new_port->next = found->ports;
				found->ports = new_port;
			}
		}
		kfree(new_elem);
	}

	write_unlock_bh(&hs_lock);
	return 0;
}  // hs_add_entry

// Remove an entry from this set
static int hs_remove_entry(struct host_set *hs, char *entry) {
	struct rb_node *node = NULL;
	struct host_set_elem *hse;
	struct host_set_elem *target;
	bool found = false;
	bool deleted = false;
	int err = 0;

	if (strlen(entry) == 0) {
		pr_err("Empty entry is not allowed\n");
		return -EINVAL;
	}  // if

	target = hse_create(entry, &err);
	if (!target) {
		pr_debug("Cannot create hostset element for delete\n");
		return err;
	}  // if

	write_lock_bh(&hs_lock);

	node = hs->hosts.rb_node;

	while (node) {
		int cmp;
		hse = rb_entry(node, struct host_set_elem, rbnode);
		cmp = cmp_hse(target, hse);
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else {
			found = true;
			break;
		}  // if
	}  // while

	if (found) {
		if (target->match_all_ports) {
			if (hse->match_all_ports) {
				deleted = true;
			}
			hse->match_all_ports = false;
		} else {
			// find same port entry and remove.
			struct port_desc *parent = NULL;
			struct port_desc *p = hse->ports;
			while (p != NULL) {
				if (port_equal(p, target->ports)) {
					if (parent == NULL) {
						// remove first entry;
						hse->ports = p->next;
					} else {
						parent->next = p->next;
					}
					kfree(p);
					deleted = true;
					break;
				}
				parent = p;
				p = p->next;
			}
		}
		// clear entry if all ports deleted and match_all_ports is false
		if (!hse->match_all_ports && hse->ports == NULL) {
			rb_erase(node, &hs->hosts);
			hs->filesize -= strlen(hse->name) + HSE_SIZE_OVERHEAD;
			kfree(hse);
		}
	}  // if

	write_unlock_bh(&hs_lock);

	free_single_hse(target);
	if (deleted) {
		return 0;
	} else {
		pr_debug("No such entry: %s\n", entry);
		return -ENOENT;
	}  // if

	return 0;
}  // hs_remove_entry

// Empty the content of the host set
static void hs_flush(struct host_set *hs) {
	struct rb_root hosts;
	write_lock_bh(&hs_lock);
	hosts = hs->hosts;
	hs->hosts = RB_ROOT;
	hs->filesize = 0;
	write_unlock_bh(&hs_lock);

	if (hosts.rb_node)
		hse_free(rb_entry(hosts.rb_node, struct host_set_elem, rbnode),
		         &hosts);
}  // hs_flush

// Free a host set entry (unconditionally)
static void _hs_destroy(struct host_set *hs) {
	hs->refcount = 0;
	pr_info(
	    "Deleting procfs file for host set /proc/net/xt_tls/hostset/%s\n",
	    hs->name);
	proc_remove(hs->proc_file);
	hs_flush(hs);
}  //_hs_destroy

void hs_destroy(struct host_set *hs) {
	if (hs->refcount) {
		_hs_destroy(hs);
	}  // if
}  // hs_destroy

// Free a host set entry (taking into account its refcount)
void hs_free(struct host_set *hs) {
	if (hs->refcount && --hs->refcount == 0) _hs_destroy(hs);
}  // hs_free

// Free a host element tree
static void hse_free(struct host_set_elem *hse, struct rb_root *root) {
	struct rb_node *node;

	// iterate through the rb tree to remove all nodes
	// always start from first to avoid potential concurrency issue
	for (node = rb_first(root); node; node = rb_first(root)) {
		struct host_set_elem *hh =
		    rb_entry(node, struct host_set_elem, rbnode);
		// erase the node from rb tree to avoid memory leak
		rb_erase(node, root);
		free_single_hse(hh);
	}  // for
}  // hse_free

static bool contains_port(struct port_desc *p, enum host_protocol protocol,
                          unsigned short port) {
	pr_debug("check port %d:%hu\n", protocol, port);
	while (p != NULL) {
		pr_debug("current prot_desc: %d:%hu-%hu\n", p->protocol, p->start, p->end);
		if (p->protocol == protocol && port >= p->start &&
		    port <= p->end) {
			return true;
		}
		p = p->next;
	}
	return false;
}

static bool hs_lookup_inner(struct host_set *hs, const char *revhostname,
                            bool is_suffix, enum host_protocol protocol,
                            unsigned short port, int record_hit) {
	struct rb_node *node;
	for (node = hs->hosts.rb_node; node;) {
		struct host_set_elem *hse =
		    rb_entry(node, struct host_set_elem, rbnode);
		int cmp = strcmp(revhostname, hse->name);
		pr_debug("compare %s with %s\n", revhostname, hse->name);
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else {
			if (!is_suffix || (is_suffix && hse->suffix_matching)) {
				if (hse->match_all_ports ||
				    contains_port(hse->ports, protocol, port)) {
					if (record_hit)
						hse->hit_count++;
					return true;
				}
			}
			if (hse->suffix_matching) {
				// try to find non-suffix match entry of the
				// same domain
				node = node->rb_left;
			} else {
				// try to find suffix match entry of the same
				// domain
				node = node->rb_right;
			}
		}
	}
	return false;
}

// Lookup the host set for the specifed host name
bool hs_lookup(struct host_set *hs, const char *hostname,
               enum host_protocol protocol, unsigned short port,
               int record_hit) {
	bool result = false;
	char revhostname[MAX_HOSTNAME_LEN + 1];
	int i;
	if (!hs->hosts.rb_node) return false;
	pr_debug("Lookup %s:%d:%hu in %s\n", hostname, protocol, port,
	         hs->name);

	strrev(revhostname, hostname, MAX_HOSTNAME_LEN);

	if (!read_trylock(&hs_lock)) return false;
	read_unlock(&hs_lock);

	read_lock_bh(&hs_lock);
	if (hs_lookup_inner(hs, revhostname, false, protocol, port, record_hit)) {
		result = true;
	} else {
		// for "moc.elgoog.www.cba", check "moc.elgoog.www",
		// "moc.elgoog", "moc" respectively
		for (i = strlen(revhostname) - 1; i > 0; i--) {
			if (revhostname[i] == '.') {
				revhostname[i] = '\0';
				pr_debug("try suffix match: %s, protocol: %d, prot: %d\n", revhostname, protocol, port);
			if (hs_lookup_inner(hs, revhostname, true,
			                    protocol, port, record_hit)) {
					result = true;
					break;
				}
			}
		}
	}

	read_unlock_bh(&hs_lock);
	return result;
}  // hs_lookup

// Reverse a string
static void strrev(char *dst, const char *src, size_t max_len) {
	const char *ps = src + strlen(src);
	char *pd = dst;
	while (ps-- > src && (pd - dst) < max_len) *pd++ = *ps;
	*pd = '\0';
}  // strrev

// Implementation of the read/write operations for the hostset proc-file

// Sequential proc file reading operations (callbacks)
static void *seq_read_start(struct seq_file *seq, loff_t *pos)
    __acquires(hs_lock) {
// https://github.com/torvalds/linux/commit/359745d78351c6f5442435f81549f0207ece28aa
// https://github.com/openzfs/zfs/issues/13004
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
	const struct host_set *hs = PDE_DATA(file_inode(seq->file));
#else
	const struct host_set *hs = pde_data(file_inode(seq->file));
#endif

	struct rb_node *node;
	loff_t p = *pos;

#ifdef XT_TLS_DEBUG
	pr_info("Seq read start: %s\n", hs->name);
#endif

	read_lock_bh(&hs_lock);

	for (node = rb_first(&hs->hosts); node; node = rb_next(node)) {
		if (p-- == 0) return node;
	}  // for

	return NULL;
}  //*seq_read_start

static void *seq_read_next(struct seq_file *seq, void *v, loff_t *pos) {
	struct rb_node *node = rb_next(v);
	(*pos)++;
	return node;
}  // seq_read_next

static void seq_read_stop(struct seq_file *seq, void *v) __releases(hs_lock) {
	read_unlock_bh(&hs_lock);
}  // seq_read_stop

static int seq_read_show(struct seq_file *seq, void *v) {
	const struct host_set_elem *hse =
	    rb_entry(v, struct host_set_elem, rbnode);
	const char *p = hse->name + strlen(hse->name);
#ifdef XT_TLS_DEBUG
	pr_info("Seq read show: %s\n", hse->name);
#endif

	seq_printf(seq, "%*llu ", HIT_COUNT_DISPL_WIDTH, hse->hit_count);
	if (hse->suffix_matching) {
		seq_printf(seq, "*.");
	}
	while (--p >= hse->name) seq_putc(seq, *p);

	if (hse->match_all_ports) {
		seq_printf(seq, " *");
	}
	if (hse->ports != NULL) {
		struct port_desc *port = hse->ports;
		seq_printf(seq, " (");
		while (port != NULL) {
			const char *protocol = "unknown";
			if (port->protocol == TCP) {
				protocol = "tcp";
			} else if (port->protocol == UDP) {
				protocol = "udp";
			}
			seq_printf(seq, "%s:%d-%d", protocol, port->start,
			           port->end);
			if (port->next != NULL) {
				seq_printf(seq, ",");
			}
			port = port->next;
		}
		seq_printf(seq, ")");
	}
	seq_putc(seq, '\n');
	return 0;
}  // seq_read_show

static const struct seq_operations seq_ops = {
    .start = seq_read_start,
    .next = seq_read_next,
    .stop = seq_read_stop,
    .show = seq_read_show,
};

static int seq_file_open(struct inode *inode, struct file *file) {
	return seq_open(file, &seq_ops);
}  // seq_file_open

// Callback for writing to the proc file
static ssize_t proc_write(struct file *file, const char __user *input,
                          size_t size, loff_t *loff) {
	struct inode *inode = file_inode(file);

// https://github.com/torvalds/linux/commit/359745d78351c6f5442435f81549f0207ece28aa
// https://github.com/openzfs/zfs/issues/13004
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
	struct host_set *hs = PDE_DATA(inode);
#else
	struct host_set *hs = pde_data(inode);
#endif

	char buf[MAX_HOSTNAME_LEN + 2];
	int rc;

	if (size == 0) return 0;
	if (size > sizeof(buf) - 1) size = sizeof(buf) - 1;
	if (copy_from_user(buf, input, size) != 0) return -EFAULT;
	buf[size] = '\0';

	/* Strict protocol! */
	if (*loff != 0) return -ESPIPE;

	switch (buf[0]) {
		case '/': /* flush table */
			hs_flush(hs);
			break;
		case '-': /* remove hostname */
			rc = hs_remove_entry(hs, strim(buf + 1));
			if (rc < 0) return rc;
			break;
		case '+': /* add hostname */
			rc = hs_add_entry(hs, strim(buf + 1));
			if (rc < 0) return rc;
			break;
		default:
			pr_err(
			    "The first char must be an opcode: '+' to add a "
			    "hostname, '-' to remove and '/' to flush the "
			    "entire set\n");
			return -EINVAL;
	}  // switch

	proc_set_size(hs->proc_file, hs->filesize);
	return size;
}  // proc_write
