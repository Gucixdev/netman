/* nl_link.c - link settings (MTU, offload, ethtool) and IPv6 (SLAAC / privacy / forwarding / PD hooks). Part of the link modules (netlink.h); shared helpers: netlink_priv.h. */
#define _GNU_SOURCE
#include "netlink.h"
#include "netlink_priv.h"
#include "net.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <linux/fib_rules.h>
#include <linux/icmp.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/veth.h>

#include "netlink_priv.h"

/* ======================================================================== link settings (MTU, offload, ethtool) */
int nl_ethtool(const char *ifn, void *data)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0), r = 0;
	if (fd < 0) return -errno;
	memset(&ifr, 0, sizeof ifr);
	nl_cpy(ifr.ifr_name, sizeof ifr.ifr_name, ifn);
	ifr.ifr_data = data;
	if (ioctl(fd, SIOCETHTOOL, &ifr) < 0) r = -errno;
	close(fd);
	return r;
}
static int nl__etv(const char *ifn, unsigned cmd, int *val, int set)
{
	struct ethtool_value v = {cmd, set ? (unsigned)*val : 0};
	int r = nl_ethtool(ifn, &v);
	if (!set && r == 0) *val = v.data;
	return r;
}
int netman_nl_link_add(const netman_ent *e)
{
	static const struct { const char *n; unsigned set; size_t off; } of[] = {
		{"tso", ETHTOOL_STSO, offsetof(netman_ent, tso)}, {"gso", ETHTOOL_SGSO, offsetof(netman_ent, gso)},
		{"gro", ETHTOOL_SGRO, offsetof(netman_ent, gro)}, {"sg", ETHTOOL_SSG, offsetof(netman_ent, sg)},
		{"rxcsum", ETHTOOL_SRXCSUM, offsetof(netman_ent, rxcsum)}, {"txcsum", ETHTOOL_STXCSUM, offsetof(netman_ent, txcsum)}};
	size_t i;
	int r, bad = 0;
	if ((r = netman_nl_check(e)) < 0) return r;
	if (nl_idx(e->name) < 0) return nl_fail(-ENODEV, "no such interface '%s'", e->name);
	if (e->mtu > 0 && (r = nl__setmtu(e->name, e->mtu)) < 0) return nl_fail(r, "mtu %d on %s: %s", e->mtu, e->name, strerror(-r));
	for (i = 0; i < sizeof of / sizeof *of; i++) {
		int v = *(const int *)((const char *)e + of[i].off);
		if (v >= 0 && (r = nl__etv(e->name, of[i].set, &v, 1)) < 0) bad = nl_fail(r, "%s on %s: %s", of[i].n, e->name, strerror(-r));
	}
	if (e->speed > 0 || e->duplex[0] || e->autoneg >= 0) {
		struct ethtool_cmd c = {.cmd = ETHTOOL_GSET};
		if ((r = nl_ethtool(e->name, &c)) < 0) return nl_fail(r, "ethtool settings on %s: %s", e->name, strerror(-r));
		c.cmd = ETHTOOL_SSET;
		if (e->autoneg >= 0) c.autoneg = e->autoneg;
		if (e->speed > 0) ethtool_cmd_speed_set(&c, e->speed);
		if (e->duplex[0]) c.duplex = !strcmp(e->duplex, "full") ? DUPLEX_FULL : DUPLEX_HALF;
		if ((r = nl_ethtool(e->name, &c)) < 0) return nl_fail(r, "ethtool settings on %s: %s", e->name, strerror(-r));
	}
	return bad;
}
int netman_nl_link_del(const netman_ent *e) { return e->mtu > 0 ? nl__setmtu(e->name, 1500) : 0; } /* back to the Ethernet default */
int netman_nl_link_show(const netman_ent *e, FILE *f)
{
	static const struct { const char *n; unsigned get; } of[] = {{"tso", ETHTOOL_GTSO}, {"gso", ETHTOOL_GGSO}, {"gro", ETHTOOL_GGRO}, {"sg", ETHTOOL_GSG}, {"rxcsum", ETHTOOL_GRXCSUM}, {"txcsum", ETHTOOL_GTXCSUM}};
	netman_nl_info i;
	size_t k;
	int r = netman_nl_getinfo(e->name, &i), v;
	if (r < 0) return r;
	fprintf(f, "%s mtu %d", e->name, i.mtu);
	for (k = 0; k < sizeof of / sizeof *of; k++)
		if (nl__etv(e->name, of[k].get, &v, 0) == 0) fprintf(f, " %s %s", of[k].n, v ? "on" : "off");
	fputc('\n', f);
	return 0;
}

/* ======================================================================== IPv6: SLAAC / privacy / forwarding / DHCPv6-PD hooks */
static int nl__sysw(const char *ifn, const char *key, int v)
{
	char p[300], d[16];
	int fd, n = snprintf(d, sizeof d, "%d\n", v);
	snprintf(p, sizeof p, "%s/sys/net/ipv6/conf/%s/%s", netman_nl_proc, ifn, key);
	if ((fd = open(p, O_WRONLY | O_CLOEXEC)) < 0) return -errno;
	if (write(fd, d, n) != n) {
		n = -errno;
		close(fd);
		return n;
	}
	close(fd);
	return 0;
}
static int nl__sysr(const char *ifn, const char *key)
{
	char p[300], b[32];
	snprintf(p, sizeof p, "%s/sys/net/ipv6/conf/%s/%s", netman_nl_proc, ifn, key);
	return nl_slurp(p, b, sizeof b) < 0 ? -1 : atoi(b);
}
int netman_nl_pd_subnet(const char *prefix, int idx, char *cidr, size_t n)
{
	nl_ip p;
	uint64_t net = 0;
	int i, bits;
	char b[64];
	if (nl_parse_ip(prefix, &p, 1) < 0 || p.fam != AF_INET6) return NL_FAIL("bad IPv6 prefix '%s'", prefix);
	if (p.plen > 64) return NL_FAIL("delegated prefix longer than /64");
	bits = 64 - p.plen;
	if (idx < 0 || (bits < 31 && idx >= (1 << bits))) return nl_fail(-ERANGE, "prefix %s has no subnet number %d", prefix, idx);
	for (i = 0; i < 8; i++) net = (net << 8) | p.b[i];
	net = (net & (p.plen ? ~0ULL << bits : 0)) | (uint64_t)idx;
	for (i = 7; i >= 0; i--, net >>= 8) p.b[i] = net & 0xff;
	memset(p.b + 8, 0, 8);
	p.b[15] = 1;
	if (!inet_ntop(AF_INET6, p.b, b, sizeof b)) return -EINVAL;
	snprintf(cidr, n, "%s/64", b);
	return 0;
}
int netman_nl_pd_from_env(const char *prefixes, netman_ent *e)
{
	char t[128], *c;
	nl_ip p;
	if (!prefixes || !*prefixes) return NL_FAIL("no prefixes");
	nl_cpy(t, sizeof t, prefixes);
	if ((c = strpbrk(t, ", "))) *c = 0; /* first entry; odhcp6c adds ",preferred,valid" */
	if (nl_parse_ip(t, &p, 1) < 0 || p.fam != AF_INET6) return NL_FAIL("bad delegated prefix '%s'", t);
	nl_cpy(e->pd_prefix, sizeof e->pd_prefix, t);
	return 0;
}
int netman_nl_pd_helper_conf(const netman_ent *e, char *out, size_t cap)
{
	struct nl_out o = {out, 0, cap};
	int i;
	if (cap) out[0] = 0;
	nl_put(&o, NL_HDR "# dnsmasq: router advertisements + stateless DHCPv6 for the delegated-prefix downstream ifaces\nenable-ra\n");
	for (i = 0; i < e->nmember; i++) nl_put(&o, "interface=%s\ndhcp-range=::,constructor:%s,ra-stateless,ra-names\n", e->member[i], e->member[i]);
	return o.n >= cap ? -E2BIG : (int)o.n;
}
int netman_nl_ipv6_add(const netman_ent *e)
{
	int r, i, bad = 0;
	char cidr[80];
	if ((r = netman_nl_check(e)) < 0) return r;
	if (nl_idx(e->name) < 0) return nl_fail(-ENODEV, "no such interface '%s'", e->name);
	if (e->accept_ra >= 0 && (r = nl__sysw(e->name, "accept_ra", e->accept_ra)) < 0) bad = nl_fail(r, "accept_ra: %s", strerror(-r));
	if (e->autoconf >= 0 && (r = nl__sysw(e->name, "autoconf", e->autoconf)) < 0) bad = nl_fail(r, "autoconf: %s", strerror(-r));
	if (e->tempaddr >= 0 && (r = nl__sysw(e->name, "use_tempaddr", e->tempaddr)) < 0) bad = nl_fail(r, "use_tempaddr: %s", strerror(-r));
	if (e->forwarding >= 0 && (r = nl__sysw(e->name, "forwarding", e->forwarding)) < 0) bad = nl_fail(r, "forwarding: %s", strerror(-r));
	if (e->addr[0] && (r = netman_addr_add(e->name, e->addr)) < 0) return r;
	if (e->pd_prefix[0])
		for (i = 0; i < e->nmember; i++) { /* DHCPv6-PD hook: one /64 per downstream iface, ::1 on it */
			if ((r = netman_nl_pd_subnet(e->pd_prefix, i + 1, cidr, sizeof cidr)) < 0) return r;
			if ((r = netman_addr_add(e->member[i], cidr)) < 0) return r;
		}
	return bad;
}
int netman_nl_ipv6_del(const netman_ent *e)
{
	int i;
	char cidr[80];
	nl__sysw(e->name, "accept_ra", 1);
	nl__sysw(e->name, "autoconf", 1);
	nl__sysw(e->name, "use_tempaddr", 0);
	nl__sysw(e->name, "forwarding", 0);
	if (e->addr[0]) netman_addr_del(e->name, e->addr);
	if (e->pd_prefix[0])
		for (i = 0; i < e->nmember; i++)
			if (netman_nl_pd_subnet(e->pd_prefix, i + 1, cidr, sizeof cidr) == 0) netman_addr_del(e->member[i], cidr);
	return 0;
}
int netman_nl_ipv6_show(const netman_ent *e, FILE *f)
{
	netman_if i;
	int k, r = netman_find(e->name, &i);
	if (r < 0) return r;
	fprintf(f, "%s ipv6: accept_ra %d autoconf %d use_tempaddr %d forwarding %d\n", e->name, nl__sysr(e->name, "accept_ra"), nl__sysr(e->name, "autoconf"), nl__sysr(e->name, "use_tempaddr"), nl__sysr(e->name, "forwarding"));
	for (k = 0; k < i.naddr; k++)
		if (strchr(i.addr[k], ':')) fprintf(f, "  %s\n", i.addr[k]);
	return 0;
}
