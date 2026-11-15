/* nl_vlan.c - vlan / QinQ / macvlan / ipvlan / veth / dummy. Part of the link modules (netlink.h); shared helpers: netlink_priv.h. */
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

/* ======================================================================== vlan / macvlan / ipvlan / veth / dummy */
int netman_nl_vlan_add(const netman_ent *e)
{
	nl_req q;
	int li, di, r, p, qinq;
	if ((r = netman_nl_check(e)) < 0) return r;
	if (e->vid < 1) return NL_FAIL("vlan needs vid=");
	if ((p = nl_idx(e->parent)) < 0) return nl_fail(p, "vlan %s: parent '%s' does not exist", e->name, e->parent);
	qinq = !strcmp(e->proto, "802.1ad");
	netman_link_set(e->parent, 1); /* a vlan cannot come up over a down lower device */
	li = nl__begin(&q, e->name, "vlan", p, e->mtu);
	di = nl__nest(&q, IFLA_INFO_DATA);
	nl__a16(&q, IFLA_VLAN_ID, e->vid);
	if (qinq) nl__a16(&q, IFLA_VLAN_PROTOCOL, htons(ETH_P_8021AD));
	nl__end(&q, di);
	nl__end(&q, li);
	if ((r = nl_nl(&q, NULL, NULL)) < 0) return nl_fail(r, "vlan %s: %s", e->name, strerror(-r));
	if (e->inner_vid > 0) { /* QinQ: a plain 802.1Q vlan riding inside the outer service tag */
		char in[16];
		int pi = nl_idx(e->name);
		netman_link_set(e->name, 1);
		nl_cpy(in, sizeof in, e->inner);
		if (!in[0] && snprintf(in, sizeof in, "%s.%d", e->name, e->inner_vid) >= (int)sizeof in) return NL_FAIL("inner vlan name too long, set inner=");
		li = nl__begin(&q, in, "vlan", pi, 0);
		di = nl__nest(&q, IFLA_INFO_DATA);
		nl__a16(&q, IFLA_VLAN_ID, e->inner_vid);
		nl__end(&q, di);
		nl__end(&q, li);
		if ((r = nl_nl(&q, NULL, NULL)) < 0) return nl_fail(r, "inner vlan %s: %s", in, strerror(-r));
		netman_link_set(in, 1);
	}
	if (e->addr[0] && (r = netman_addr_add(e->name, e->addr)) < 0) return r;
	return netman_link_set(e->name, 1);
}
int netman_nl_vlan_del(const netman_ent *e) { return nl__dellink(e->name); } /* deleting the outer removes the inner */
int netman_nl_vlan_show(const netman_ent *e, FILE *f)
{
	netman_nl_info i;
	char b[IF_NAMESIZE];
	int r = netman_nl_getinfo(e->name, &i);
	if (r < 0) return r;
	fprintf(f, "%s vlan %d on %s proto %s\n", e->name, i.vid, i.link > 0 && if_indextoname(i.link, b) ? b : "?", i.proto == 0x88a8 ? "802.1ad" : "802.1Q");
	return 0;
}

struct nl_mode { const char *n; int v; };
static const struct nl_mode nl__mvmodes[] = {{"private", MACVLAN_MODE_PRIVATE}, {"vepa", MACVLAN_MODE_VEPA}, {"bridge", MACVLAN_MODE_BRIDGE}, {"passthru", MACVLAN_MODE_PASSTHRU}, {"source", MACVLAN_MODE_SOURCE}};
static const struct nl_mode nl__ipmodes[] = {{"l2", IPVLAN_MODE_L2}, {"l3", IPVLAN_MODE_L3}, {"l3s", IPVLAN_MODE_L3S}};
static int nl__mode(const char *m, const char *dflt, const struct nl_mode *t, int n, int *out)
{
	int i;
	if (!*m) m = dflt;
	for (i = 0; i < n; i++)
		if (!strcmp(m, t[i].n)) return *out = t[i].v, 0;
	return NL_FAIL("bad mode '%s'", m);
}
static int nl__vlandev(const netman_ent *e, const char *kind)
{
	nl_req q;
	int li, di, r, p, mode = 0;
	if ((r = netman_nl_check(e)) < 0) return r;
	if ((p = nl_idx(e->parent)) < 0) return nl_fail(p, "%s %s: parent '%s' does not exist", kind, e->name, e->parent);
	if (!strcmp(kind, "macvlan") ? nl__mode(e->mode, "bridge", nl__mvmodes, 5, &mode) : nl__mode(e->mode, "l2", nl__ipmodes, 3, &mode)) return -EINVAL;
	netman_link_set(e->parent, 1);
	li = nl__begin(&q, e->name, kind, p, e->mtu);
	di = nl__nest(&q, IFLA_INFO_DATA);
	if (!strcmp(kind, "macvlan")) nl__a32(&q, IFLA_MACVLAN_MODE, mode);
	else nl__a16(&q, IFLA_IPVLAN_MODE, mode);
	nl__end(&q, di);
	nl__end(&q, li);
	if ((r = nl_nl(&q, NULL, NULL)) < 0) return nl_fail(r, "%s %s: %s", kind, e->name, strerror(-r));
	if (e->addr[0] && (r = netman_addr_add(e->name, e->addr)) < 0) return r;
	return netman_link_set(e->name, 1);
}
int netman_nl_macvlan_add(const netman_ent *e) { return nl__vlandev(e, "macvlan"); }
int netman_nl_ipvlan_add(const netman_ent *e) { return nl__vlandev(e, "ipvlan"); }
int netman_nl_macvlan_del(const netman_ent *e) { return nl__dellink(e->name); }
int netman_nl_ipvlan_del(const netman_ent *e) { return nl__dellink(e->name); }
static int nl__vshow(const netman_ent *e, FILE *f, const struct nl_mode *t, int n)
{
	netman_nl_info i;
	char b[IF_NAMESIZE];
	int r = netman_nl_getinfo(e->name, &i), k;
	if (r < 0) return r;
	fprintf(f, "%s %s on %s mode ", e->name, i.kind, i.link > 0 && if_indextoname(i.link, b) ? b : "?");
	for (k = 0; k < n; k++)
		if (t[k].v == i.mode) fputs(t[k].n, f);
	fputc('\n', f);
	return 0;
}
int netman_nl_macvlan_show(const netman_ent *e, FILE *f) { return nl__vshow(e, f, nl__mvmodes, 5); }
int netman_nl_ipvlan_show(const netman_ent *e, FILE *f) { return nl__vshow(e, f, nl__ipmodes, 3); }

int netman_nl_veth_add(const netman_ent *e)
{
	nl_req q;
	int li, di, pe, r;
	if ((r = netman_nl_check(e)) < 0) return r;
	if (!nl__nm(e->peer)) return NL_FAIL("veth needs peer=");
	li = nl__begin(&q, e->name, "veth", 0, e->mtu);
	di = nl__nest(&q, IFLA_INFO_DATA);
	pe = nl__nest(&q, VETH_INFO_PEER);
	{ /* the peer attribute carries a bare ifinfomsg followed by the peer's own attributes */
		int start = NLMSG_ALIGN(q.h.nlmsg_len);
		memset((char *)&q + start, 0, sizeof(struct ifinfomsg));
		q.h.nlmsg_len = start + sizeof(struct ifinfomsg);
	}
	nl__astr(&q, IFLA_IFNAME, e->peer);
	if (e->netns_pid > 0) nl__a32(&q, IFLA_NET_NS_PID, e->netns_pid);
	nl__end(&q, pe);
	nl__end(&q, di);
	nl__end(&q, li);
	if ((r = nl_nl(&q, NULL, NULL)) < 0) return nl_fail(r, "veth %s: %s", e->name, strerror(-r));
	if (e->addr[0] && (r = netman_addr_add(e->name, e->addr)) < 0) return r;
	return netman_link_set(e->name, 1);
}
int netman_nl_veth_del(const netman_ent *e) { return nl__dellink(e->name); } /* the kernel removes the peer too */
int netman_nl_veth_show(const netman_ent *e, FILE *f)
{
	netman_nl_info i;
	char b[IF_NAMESIZE];
	int r = netman_nl_getinfo(e->name, &i);
	if (r < 0) return r;
	fprintf(f, "%s veth peer %s mtu %d %s\n", e->name, i.link > 0 && if_indextoname(i.link, b) ? b : "(other netns)", i.mtu, i.up ? "up" : "down");
	return 0;
}

int netman_nl_dummy_add(const netman_ent *e)
{
	nl_req q;
	int li, r;
	if ((r = netman_nl_check(e)) < 0) return r;
	li = nl__begin(&q, e->name, "dummy", 0, e->mtu);
	nl__end(&q, li);
	if ((r = nl_nl(&q, NULL, NULL)) < 0) return nl_fail(r, "dummy %s: %s", e->name, strerror(-r));
	if (e->addr[0] && (r = netman_addr_add(e->name, e->addr)) < 0) return r;
	return netman_link_set(e->name, 1);
}
int netman_nl_dummy_del(const netman_ent *e) { return nl__dellink(e->name); }
int netman_nl_dummy_show(const netman_ent *e, FILE *f)
{
	netman_nl_info i;
	int r = netman_nl_getinfo(e->name, &i);
	if (r < 0) return r;
	fprintf(f, "%s dummy mtu %d %s\n", e->name, i.mtu, i.up ? "up" : "down");
	return 0;
}
