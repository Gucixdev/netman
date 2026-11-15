/* nl_route.c - routes, rules, tables and ECMP multi-uplink failover. Part of the link modules (netlink.h); shared helpers: netlink_priv.h. */
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

/* ======================================================================== routes, rules, tables */
int netman_nl_table_id(const char *s)
{
	char line[128], nm[64];
	FILE *f;
	int t = -1, n;
	if (!s || !*s) return -1;
	if (s[0] >= '0' && s[0] <= '9') return atoi(s);
	if (!strcmp(s, "main")) return (int)RT_TABLE_MAIN;
	if (!strcmp(s, "local")) return RT_TABLE_LOCAL;
	if (!strcmp(s, "default")) return RT_TABLE_DEFAULT;
	if ((f = fopen(netman_nl_rt_tables, "r"))) {
		while (fgets(line, sizeof line, f))
			if (line[0] != '#' && sscanf(line, "%d %63s", &n, nm) == 2 && !strcmp(nm, s)) t = n;
		fclose(f);
	}
	return t;
}
static void nl__rtmsg_table(nl_req *q, int table)
{
	q->m.r.rtm_table = table > 255 ? (int)RT_TABLE_UNSPEC : table;
	nl__a32(q, RTA_TABLE, table);
}
static int nl__route(int op, const netman_ent *e, int onlink)
{
	nl_req q;
	nl_ip d, g;
	int oif = 0, has_gw = e->gateway[0], deflt = !e->dst[0] || !strcmp(e->dst, "default"), table = e->table > 0 ? e->table : (int)RT_TABLE_MAIN;
	int type = RTN_UNICAST, del = op == RTM_DELROUTE;
	memset(&d, 0, sizeof d);
	if (e->rtype[0]) {
		if (!strcmp(e->rtype, "blackhole")) type = RTN_BLACKHOLE;
		else if (!strcmp(e->rtype, "unreachable")) type = RTN_UNREACHABLE;
		else if (!strcmp(e->rtype, "prohibit")) type = RTN_PROHIBIT;
		else if (strcmp(e->rtype, "unicast")) return NL_FAIL("bad rtype '%s'", e->rtype);
	}
	if (has_gw && nl_parse_ip(e->gateway, &g, 0) < 0) return NL_FAIL("bad gateway '%s'", e->gateway);
	if (!deflt && nl_parse_ip(e->dst, &d, 1) < 0) return NL_FAIL("bad dst '%s'", e->dst);
	if (deflt) {
		d.fam = has_gw ? g.fam : AF_INET;
		d.plen = 0;
	}
	if (has_gw && g.fam != d.fam) return NL_FAIL("address family mismatch in route");
	if (e->name[0] && type == RTN_UNICAST && (oif = nl_idx(e->name)) < 0) return nl_fail(oif, "no such interface '%s'", e->name);
	nl_req_init(&q, op, NLM_F_ACK | (op == RTM_NEWROUTE ? NLM_F_CREATE | NLM_F_REPLACE : 0), sizeof(struct rtmsg));
	q.m.r.rtm_family = d.fam;
	q.m.r.rtm_dst_len = d.plen;
	q.m.r.rtm_protocol = del ? 0 : RTPROT_STATIC;
	q.m.r.rtm_scope = del ? RT_SCOPE_NOWHERE : (type != RTN_UNICAST || has_gw) ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
	q.m.r.rtm_type = del ? 0 : type;
	if (onlink) q.m.r.rtm_flags |= RTNH_F_ONLINK;
	nl__rtmsg_table(&q, table);
	if (d.plen) nl_attr(&q, RTA_DST, d.b, nl_iplen(&d));
	if (e->src[0]) {
		nl_ip s;
		if (nl_parse_ip(e->src, &s, 0) < 0 || s.fam != d.fam) return NL_FAIL("bad src '%s'", e->src);
		nl_attr(&q, RTA_PREFSRC, s.b, nl_iplen(&s));
	}
	if (has_gw) nl_attr(&q, RTA_GATEWAY, g.b, nl_iplen(&g));
	if (oif > 0) nl__a32(&q, RTA_OIF, oif);
	if (e->metric > 0) nl__a32(&q, RTA_PRIORITY, e->metric);
	return nl_nl(&q, NULL, NULL);
}
int netman_nl_route_add(const netman_ent *e)
{
	int r = nl__route(RTM_NEWROUTE, e, 0);
	if ((r == -ENETUNREACH || r == -EINVAL) && e->gateway[0] && e->name[0]) r = nl__route(RTM_NEWROUTE, e, 1); /* /32 leases etc. */
	return r < 0 && r != -EINVAL ? nl_fail(r, "route: %s", strerror(-r)) : r;
}
int netman_nl_route_del(const netman_ent *e)
{
	int r = nl__route(RTM_DELROUTE, e, 0);
	return r == -ESRCH ? 0 : r;
}

struct nl_rctx { struct nl_out o; int table, fam; };
static void nl__route_cb(const struct nlmsghdr *m, void *u)
{
	struct nl_rctx *c = u;
	struct rtmsg *r = NLMSG_DATA(m);
	struct rtattr *tb[RTA_MAX + 1];
	char b[64], n[IF_NAMESIZE];
	int tab;
	if (m->nlmsg_type != RTM_NEWROUTE) return;
	nl__rta(tb, RTA_MAX, RTM_RTA(r), RTM_PAYLOAD(m));
	tab = tb[RTA_TABLE] ? (int)nl__u(tb[RTA_TABLE]) : r->rtm_table;
	if ((c->table && tab != c->table) || (c->fam && r->rtm_family != c->fam)) return;
	if (tb[RTA_DST]) {
		inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_DST]), b, sizeof b);
		nl_put(&c->o, "%s/%d", b, r->rtm_dst_len);
	} else nl_put(&c->o, "default");
	if (r->rtm_type != RTN_UNICAST) nl_put(&c->o, " type %s", r->rtm_type == RTN_BLACKHOLE ? "blackhole" : r->rtm_type == RTN_UNREACHABLE ? "unreachable" : r->rtm_type == RTN_PROHIBIT ? "prohibit" : "other");
	if (tb[RTA_MULTIPATH]) {
		struct rtnexthop *nh = RTA_DATA(tb[RTA_MULTIPATH]);
		int len = RTA_PAYLOAD(tb[RTA_MULTIPATH]);
		if (tb[RTA_PRIORITY]) nl_put(&c->o, " metric %u", nl__u(tb[RTA_PRIORITY]));
		while (len >= (int)sizeof *nh && nh->rtnh_len >= sizeof *nh && (int)nh->rtnh_len <= len) {
			struct rtattr *g[RTA_MAX + 1];
			nl__rta(g, RTA_MAX, RTNH_DATA(nh), nh->rtnh_len - sizeof *nh);
			nl_put(&c->o, " nexthop");
			if (g[RTA_GATEWAY]) {
				inet_ntop(r->rtm_family, RTA_DATA(g[RTA_GATEWAY]), b, sizeof b);
				nl_put(&c->o, " via %s", b);
			}
			nl_put(&c->o, " dev %s weight %d", if_indextoname(nh->rtnh_ifindex, n) ? n : "?", nh->rtnh_hops + 1);
			len -= RTNH_ALIGN(nh->rtnh_len);
			nh = RTNH_NEXT(nh);
		}
	} else {
		if (tb[RTA_GATEWAY]) {
			inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_GATEWAY]), b, sizeof b);
			nl_put(&c->o, " via %s", b);
		}
		if (tb[RTA_OIF]) nl_put(&c->o, " dev %s", if_indextoname(nl__u(tb[RTA_OIF]), n) ? n : "?");
		if (tb[RTA_PRIORITY]) nl_put(&c->o, " metric %u", nl__u(tb[RTA_PRIORITY]));
	}
	nl_put(&c->o, " table %d\n", tab);
}
int netman_nl_route_list(int table, int family, char *out, size_t cap)
{
	struct nl_rctx c = {{out, 0, cap}, table, family};
	nl_req q;
	int r;
	if (cap) out[0] = 0;
	nl_req_init(&q, RTM_GETROUTE, NLM_F_DUMP, sizeof(struct rtmsg));
	q.m.r.rtm_family = AF_UNSPEC;
	if ((r = nl_nl(&q, nl__route_cb, &c)) < 0) return r;
	return (int)c.o.n;
}
int netman_nl_route_show(const netman_ent *e, FILE *f)
{
	char b[8192];
	int n = netman_nl_route_list(e->table > 0 ? e->table : (int)RT_TABLE_MAIN, 0, b, sizeof b);
	if (n < 0) return n;
	fputs(b, f);
	return 0;
}

static int nl__rule(int op, const netman_ent *e)
{
	nl_req q;
	struct fib_rule_hdr *h;
	nl_ip a;
	int fam = AF_INET;
	if (e->from[0] && nl_parse_ip(e->from, &a, 0) == 0) fam = a.fam;
	else if (e->to[0] && nl_parse_ip(e->to, &a, 0) == 0) fam = a.fam;
	if (e->table <= 0) return NL_FAIL("rule needs table=");
	nl_req_init(&q, op, NLM_F_ACK | (op == RTM_NEWRULE ? NLM_F_CREATE | NLM_F_EXCL : 0), sizeof(struct fib_rule_hdr));
	h = (struct fib_rule_hdr *)NLMSG_DATA(&q.h);
	h->family = fam;
	h->action = FR_ACT_TO_TBL;
	if (e->from[0]) {
		if (nl_parse_ip(e->from, &a, 0) < 0 || a.fam != fam) return NL_FAIL("bad from '%s'", e->from);
		h->src_len = a.plen < 0 ? (fam == AF_INET ? 32 : 128) : a.plen;
		nl_attr(&q, FRA_SRC, a.b, nl_iplen(&a));
	}
	if (e->to[0]) {
		if (nl_parse_ip(e->to, &a, 0) < 0 || a.fam != fam) return NL_FAIL("bad to '%s'", e->to);
		h->dst_len = a.plen < 0 ? (fam == AF_INET ? 32 : 128) : a.plen;
		nl_attr(&q, FRA_DST, a.b, nl_iplen(&a));
	}
	if (e->iif[0]) nl__astr(&q, FRA_IIFNAME, e->iif);
	if (e->oif[0]) nl__astr(&q, FRA_OIFNAME, e->oif);
	if (e->fwmark) {
		nl__a32(&q, FRA_FWMARK, e->fwmark);
		nl__a32(&q, FRA_FWMASK, 0xffffffffu);
	}
	if (e->prio > 0) nl__a32(&q, FRA_PRIORITY, e->prio);
	h->table = e->table > 255 ? 0 : e->table;
	nl__a32(&q, FRA_TABLE, e->table);
	return nl_nl(&q, NULL, NULL);
}
int netman_nl_rule_add(const netman_ent *e)
{
	int r = nl__rule(RTM_NEWRULE, e);
	return r == -EEXIST ? 0 : r;
}
int netman_nl_rule_del(const netman_ent *e)
{
	int r = nl__rule(RTM_DELRULE, e);
	return r == -ENOENT ? 0 : r;
}
static void nl__rule_cb(const struct nlmsghdr *m, void *u)
{
	struct nl_rctx *c = u;
	struct fib_rule_hdr *h = NLMSG_DATA(m);
	struct rtattr *tb[FRA_MAX + 1];
	char b[64];
	if (m->nlmsg_type != RTM_NEWRULE || (c->fam && h->family != c->fam)) return;
	nl__rta(tb, FRA_MAX, (struct rtattr *)((char *)h + NLMSG_ALIGN(sizeof *h)), m->nlmsg_len - NLMSG_LENGTH(sizeof *h));
	nl_put(&c->o, "%u:", tb[FRA_PRIORITY] ? nl__u(tb[FRA_PRIORITY]) : 0);
	if (tb[FRA_SRC]) { inet_ntop(h->family, RTA_DATA(tb[FRA_SRC]), b, sizeof b); nl_put(&c->o, " from %s/%d", b, h->src_len); }
	if (tb[FRA_DST]) { inet_ntop(h->family, RTA_DATA(tb[FRA_DST]), b, sizeof b); nl_put(&c->o, " to %s/%d", b, h->dst_len); }
	if (tb[FRA_FWMARK]) nl_put(&c->o, " fwmark 0x%x", nl__u(tb[FRA_FWMARK]));
	if (tb[FRA_IIFNAME]) nl_put(&c->o, " iif %s", (char *)RTA_DATA(tb[FRA_IIFNAME]));
	if (tb[FRA_OIFNAME]) nl_put(&c->o, " oif %s", (char *)RTA_DATA(tb[FRA_OIFNAME]));
	nl_put(&c->o, " lookup %u\n", tb[FRA_TABLE] ? nl__u(tb[FRA_TABLE]) : h->table);
}
int netman_nl_rule_list(int family, char *out, size_t cap)
{
	struct nl_rctx c = {{out, 0, cap}, 0, family};
	nl_req q;
	int r;
	if (cap) out[0] = 0;
	nl_req_init(&q, RTM_GETRULE, NLM_F_DUMP, sizeof(struct fib_rule_hdr));
	((struct fib_rule_hdr *)NLMSG_DATA(&q.h))->family = family;
	if ((r = nl_nl(&q, nl__rule_cb, &c)) < 0) return r;
	return (int)c.o.n;
}
int netman_nl_rule_show(const netman_ent *e, FILE *f)
{
	char b[8192];
	int n = netman_nl_rule_list(0, b, sizeof b);
	(void)e;
	if (n < 0) return n;
	fputs(b, f);
	return 0;
}

/* ======================================================================== ECMP multi-uplink with failover */
static uint16_t nl__cksum(const void *p, int n)
{
	const uint8_t *b = p;
	uint32_t s = 0;
	for (; n > 1; n -= 2, b += 2) s += (b[0] << 8) | b[1];
	if (n) s += b[0] << 8;
	while (s >> 16) s = (s & 0xffff) + (s >> 16);
	return htons(~s);
}
int nl__icmp_probe(const char *ifn, const char *target, int timeout_ms)
{
	struct sockaddr_in to = {.sin_family = AF_INET};
	struct { struct icmphdr h; char pad[16]; } pkt;
	static unsigned short seq;
	long end;
	int fd, ok = -ETIMEDOUT;
	uint16_t id = (uint16_t)getpid();
	if (inet_pton(AF_INET, target, &to.sin_addr) != 1) return -EINVAL;
	if ((fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP)) < 0) return -errno;
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifn, strlen(ifn) + 1) < 0) { ok = -errno; close(fd); return ok; }
	memset(&pkt, 0, sizeof pkt);
	pkt.h.type = ICMP_ECHO;
	pkt.h.un.echo.id = htons(id);
	pkt.h.un.echo.sequence = htons(++seq);
	pkt.h.checksum = nl__cksum(&pkt, sizeof pkt);
	if (sendto(fd, &pkt, sizeof pkt, 0, (struct sockaddr *)&to, sizeof to) < 0) { ok = -errno; close(fd); return ok; }
	end = nl_ms() + timeout_ms;
	for (;;) {
		struct pollfd p = {fd, POLLIN, 0};
		unsigned char buf[256];
		long left = end - nl_ms();
		ssize_t n;
		if (left <= 0 || poll(&p, 1, (int)left) <= 0) break;
		n = recv(fd, buf, sizeof buf, 0);
		if (n >= 28) {
			struct iphdr *ip = (struct iphdr *)buf;
			struct icmphdr *ic = (struct icmphdr *)(buf + ip->ihl * 4);
			if (ip->saddr == to.sin_addr.s_addr && ic->type == ICMP_ECHOREPLY && ic->un.echo.id == htons(id) && ic->un.echo.sequence == htons(seq)) { ok = 0; break; }
		}
	}
	close(fd);
	return ok;
}

static int nl__ecmp_install(const netman_ent *e)
{
	nl_req q;
	nl_ip g[NETMAN_NL_UPLINKS];
	int ix[NETMAN_NL_UPLINKS], n = 0, i, table = e->table > 0 ? e->table : (int)RT_TABLE_MAIN, metric = e->metric > 0 ? e->metric : 50, fam = 0, r, mp;
	for (i = 0; i < e->nup; i++) {
		if (!e->up[i].up) continue;
		if (nl_parse_ip(e->up[i].gw, &g[n], 0) < 0) return NL_FAIL("bad uplink gateway '%s'", e->up[i].gw);
		if (fam && g[n].fam != fam) return NL_FAIL("uplinks must share one address family");
		if (nl_idx(e->up[i].ifn) < 0) continue;
		fam = g[n].fam;
		ix[n++] = i;
	}
	nl_req_init(&q, n ? RTM_NEWROUTE : RTM_DELROUTE, NLM_F_ACK | (n ? NLM_F_CREATE | NLM_F_REPLACE : 0), sizeof(struct rtmsg));
	q.m.r.rtm_family = fam ? fam : AF_INET;
	q.m.r.rtm_protocol = n ? RTPROT_STATIC : 0;
	q.m.r.rtm_scope = n ? RT_SCOPE_UNIVERSE : RT_SCOPE_NOWHERE;
	q.m.r.rtm_type = n ? RTN_UNICAST : 0;
	nl__rtmsg_table(&q, table);
	nl__a32(&q, RTA_PRIORITY, metric);
	if (n == 1) {
		nl_attr(&q, RTA_GATEWAY, g[0].b, nl_iplen(&g[0]));
		nl__a32(&q, RTA_OIF, nl_idx(e->up[ix[0]].ifn));
	} else if (n > 1) {
		mp = nl__nest(&q, RTA_MULTIPATH);
		for (i = 0; i < n; i++) {
			int start = NLMSG_ALIGN(q.h.nlmsg_len);
			struct rtnexthop *nh = (struct rtnexthop *)((char *)&q + start);
			int w = e->up[ix[i]].weight > 0 ? e->up[ix[i]].weight : 1;
			if ((size_t)start + 64 > sizeof q) return nl_fail(-E2BIG, "too many uplinks");
			memset(nh, 0, sizeof *nh);
			nh->rtnh_hops = w - 1;
			nh->rtnh_ifindex = nl_idx(e->up[ix[i]].ifn);
			q.h.nlmsg_len = start + sizeof *nh;
			nl_attr(&q, RTA_GATEWAY, g[i].b, nl_iplen(&g[i]));
			nh->rtnh_len = q.h.nlmsg_len - start;
		}
		nl__end(&q, mp);
	}
	r = nl_nl(&q, NULL, NULL);
	if (!n && (r == -ESRCH || r == -ENOENT)) r = 0;
	if (r < 0) return nl_fail(r, "default route: %s", strerror(-r));
	return n;
}
static void nl__ecmp_defaults(netman_ent *e)
{
	int i;
	if (e->probe_ms <= 0) e->probe_ms = 1000;
	if (e->fail_after <= 0) e->fail_after = 3;
	if (e->ok_after <= 0) e->ok_after = 2;
	for (i = 0; i < e->nup; i++)
		if (e->up[i].weight <= 0) e->up[i].weight = 1;
}
int netman_nl_ecmp_tick(netman_ent *e, int force)
{
	int i, changed = 0, r;
	nl__ecmp_defaults(e);
	for (i = 0; i < e->nup; i++) {
		netman_nl_uplink *u = &e->up[i];
		netman_if f;
		int alive = netman_find(u->ifn, &f) == 0 && f.up && f.carrier;
		if (alive) alive = netman_nl_probe_fn(u->ifn, u->probe[0] ? u->probe : u->gw, e->probe_ms) == 0;
		if (alive) {
			u->fails = 0;
			if (++u->oks >= e->ok_after && !u->up) u->up = 1, changed++;
		} else {
			u->oks = 0;
			if (++u->fails >= e->fail_after && u->up) u->up = 0, changed++;
		}
		if (u->fails > 1000) u->fails = 1000;
		if (u->oks > 1000) u->oks = 1000;
	}
	if (changed || force) {
		if ((r = nl__ecmp_install(e)) < 0) return r;
	}
	return changed;
}
int netman_nl_ecmp_run(netman_ent *e, int interval_ms, volatile sig_atomic_t *stop)
{
	int r = netman_nl_ecmp_tick(e, 1);
	if (r < 0) return r;
	while (!*stop) {
		struct timespec ts = {interval_ms / 1000, (interval_ms % 1000) * 1000000L};
		nanosleep(&ts, NULL);
		if (netman_nl_ecmp_tick(e, 0) < 0) fprintf(stderr, "netman: ecmp: %s\n", netman_nl_error());
	}
	return 0;
}
int netman_nl_ecmp_add(const netman_ent *e)
{
	netman_ent tmp = *e;
	int i, r;
	if ((r = netman_nl_check(e)) < 0) return r;
	if (!tmp.nup) return NL_FAIL("ecmp needs at least one uplink=");
	nl__ecmp_defaults(&tmp);
	for (i = 0; i < tmp.nup; i++) tmp.up[i].up = 1; /* optimistic first install; the first ticks correct it */
	return nl__ecmp_install(&tmp) < 0 ? -EINVAL : 0;
}
int netman_nl_ecmp_del(const netman_ent *e)
{
	netman_ent tmp = *e;
	int i;
	for (i = 0; i < tmp.nup; i++) tmp.up[i].up = 0;
	return nl__ecmp_install(&tmp) < 0 ? -EINVAL : 0;
}
int netman_nl_ecmp_show(const netman_ent *e, FILE *f)
{
	char b[4096];
	int i;
	for (i = 0; i < e->nup; i++)
		fprintf(f, "uplink %s via %s probe %s weight %d: %s\n", e->up[i].ifn, e->up[i].gw, e->up[i].probe[0] ? e->up[i].probe : e->up[i].gw, e->up[i].weight, e->up[i].up ? "up" : "DOWN");
	if (netman_nl_route_list(e->table > 0 ? e->table : (int)RT_TABLE_MAIN, 0, b, sizeof b) > 0) fputs(b, f);
	return 0;
}
