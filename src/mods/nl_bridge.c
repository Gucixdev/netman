/* nl_bridge.c - bridges: STP, vlan filtering, per-port vlans. Part of the link modules (netlink.h); shared helpers: netlink_priv.h. */
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

/* ======================================================================== bridge */
static int nl__brvlan(int op, const char *port, int vid, int pvid, int untagged)
{
	nl_req q;
	struct bridge_vlan_info vi = {0};
	int i = nl_idx(port), af;
	if (i < 0) return i;
	vi.vid = vid;
	vi.flags = (pvid ? BRIDGE_VLAN_INFO_PVID : 0) | (untagged ? BRIDGE_VLAN_INFO_UNTAGGED : 0);
	nl_req_init(&q, op, NLM_F_ACK, sizeof(struct ifinfomsg));
	q.m.i.ifi_family = AF_BRIDGE;
	q.m.i.ifi_index = i;
	af = nl__nest(&q, IFLA_AF_SPEC);
	nl_attr(&q, IFLA_BRIDGE_VLAN_INFO, &vi, sizeof vi);
	nl__end(&q, af);
	return nl_nl(&q, NULL, NULL);
}
int netman_nl_bridge_add(const netman_ent *e)
{
	nl_req q;
	int li, di, r, i, k, bi;
	if ((r = netman_nl_check(e)) < 0) return r;
	li = nl__begin(&q, e->name, "bridge", 0, e->mtu);
	di = nl__nest(&q, IFLA_INFO_DATA);
	if (e->stp >= 0) nl__a32(&q, IFLA_BR_STP_STATE, e->stp);
	if (e->fwd_delay > 0) nl__a32(&q, IFLA_BR_FORWARD_DELAY, e->fwd_delay * 100); /* USER_HZ ticks */
	if (e->vlan_filtering >= 0) nl__a8(&q, IFLA_BR_VLAN_FILTERING, e->vlan_filtering);
	nl__end(&q, di);
	nl__end(&q, li);
	if ((r = nl_nl(&q, NULL, NULL)) < 0) return nl_fail(r, "bridge %s: %s", e->name, strerror(-r));
	bi = nl_idx(e->name);
	for (i = 0; i < e->nmember; i++) {
		if ((r = nl__enslave(e->member[i], bi)) < 0) return r;
		for (k = 0; k < e->nvlan; k++)
			if ((r = nl__brvlan(RTM_SETLINK, e->member[i], e->vlan[k].vid, e->vlan[k].pvid, e->vlan[k].untagged)) < 0)
				return nl_fail(r, "vlan %d on %s: %s", e->vlan[k].vid, e->member[i], strerror(-r));
	}
	if (e->addr[0] && (r = netman_addr_add(e->name, e->addr)) < 0) return r;
	return netman_link_set(e->name, 1);
}
int netman_nl_bridge_del(const netman_ent *e) { return nl__dellink(e->name); }
struct nl_brv { int idx, n, max; netman_nl_vlan *v; };
static void nl__brv_cb(const struct nlmsghdr *m, void *u)
{
	struct nl_brv *c = u;
	struct ifinfomsg *i = NLMSG_DATA(m);
	struct rtattr *tb[64], *a;
	int len;
	if (m->nlmsg_type != RTM_NEWLINK || i->ifi_index != c->idx) return;
	nl__rta(tb, 63, IFLA_RTA(i), IFLA_PAYLOAD(m));
	if (!tb[IFLA_AF_SPEC]) return;
	a = RTA_DATA(tb[IFLA_AF_SPEC]);
	len = RTA_PAYLOAD(tb[IFLA_AF_SPEC]);
	for (; RTA_OK(a, len); a = RTA_NEXT(a, len))
		if (a->rta_type == IFLA_BRIDGE_VLAN_INFO && c->n < c->max && RTA_PAYLOAD(a) >= sizeof(struct bridge_vlan_info)) {
			struct bridge_vlan_info *v = RTA_DATA(a);
			c->v[c->n].vid = v->vid;
			c->v[c->n].pvid = !!(v->flags & BRIDGE_VLAN_INFO_PVID);
			c->v[c->n].untagged = !!(v->flags & BRIDGE_VLAN_INFO_UNTAGGED);
			c->n++;
		}
}
int netman_nl_bridge_vlans(const char *port, netman_nl_vlan *out, int max)
{
	struct nl_brv c = {nl_idx(port), 0, max, out};
	nl_req q;
	int r;
	if (c.idx < 0) return c.idx;
	nl_req_init(&q, RTM_GETLINK, NLM_F_DUMP, sizeof(struct ifinfomsg));
	q.m.i.ifi_family = AF_BRIDGE;
	nl__a32(&q, IFLA_EXT_MASK, RTEXT_FILTER_BRVLAN);
	if ((r = nl_nl(&q, nl__brv_cb, &c)) < 0) return r;
	return c.n;
}
int netman_nl_bridge_show(const netman_ent *e, FILE *f)
{
	netman_nl_info i;
	char m[NETMAN_NL_MEMBERS * 2][16];
	netman_nl_vlan v[NETMAN_NL_VLANS];
	int n, k, j, nv, r = netman_nl_getinfo(e->name, &i);
	if (r < 0) return r;
	fprintf(f, "%s bridge: stp %s forward_delay %ds vlan_filtering %s\n", e->name, i.stp > 0 ? "on" : "off", i.fwd_delay / 100, i.vlan_filtering > 0 ? "on" : "off");
	n = netman_nl_members(e->name, m, NETMAN_NL_MEMBERS * 2);
	for (k = 0; k < n; k++) {
		fprintf(f, "  port %s", m[k]);
		nv = netman_nl_bridge_vlans(m[k], v, NETMAN_NL_VLANS);
		for (j = 0; j < nv; j++) fprintf(f, " vlan %d%s%s", v[j].vid, v[j].pvid ? " pvid" : "", v[j].untagged ? " untagged" : "");
		fputc('\n', f);
	}
	return 0;
}
