/* nl_bond.c - bonding / team (kinds bond, team). Part of the link modules (netlink.h); shared helpers: netlink_priv.h. */
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

/* ======================================================================== bonding / team */
int netman_nl_bond_add(const netman_ent *e)
{
	nl_req q;
	int li, di, r, i, mode, pi = 0;
	if ((r = netman_nl_check(e)) < 0) return r;
	mode = nl__bond_mode(e);
	if (e->primary[0] && (pi = nl_idx(e->primary)) < 0) return nl_fail(pi, "primary '%s' does not exist", e->primary);
	li = nl__begin(&q, e->name, "bond", 0, e->mtu);
	di = nl__nest(&q, IFLA_INFO_DATA);
	nl__a8(&q, IFLA_BOND_MODE, mode);
	nl__a32(&q, IFLA_BOND_MIIMON, e->miimon > 0 ? e->miimon : 100);
	if (pi > 0) nl__a32(&q, IFLA_BOND_PRIMARY, pi);
	if (e->lacp_rate[0]) nl__a8(&q, IFLA_BOND_AD_LACP_RATE, !strcmp(e->lacp_rate, "fast"));
	if (e->hash[0])
		for (i = 0; i < 6; i++)
			if (!strcmp(e->hash, nl__bhash[i])) nl__a8(&q, IFLA_BOND_XMIT_HASH_POLICY, i);
	nl__end(&q, di);
	nl__end(&q, li);
	if ((r = nl_nl(&q, NULL, NULL)) < 0) return nl_fail(r, "bond %s: %s", e->name, strerror(-r));
	{
		int bi = nl_idx(e->name);
		for (i = 0; i < e->nmember; i++)
			if ((r = nl__enslave(e->member[i], bi)) < 0) return r;
	}
	if (e->addr[0] && (r = netman_addr_add(e->name, e->addr)) < 0) return r;
	return netman_link_set(e->name, 1);
}
int netman_nl_bond_del(const netman_ent *e) { return nl__dellink(e->name); }
/* add / remove ONE slave of a live bond (bonding.c re-exports this) */
int netman_nl_bond_slave(const char *bond, const char *slave, int add)
{
	nl_req q;
	int bi = nl_idx(bond), si = nl_idx(slave), r;
	if (bi < 0) return nl_fail(bi, "no such bond '%s'", bond);
	if (si < 0) return nl_fail(si, "no such interface '%s'", slave);
	if (add) return nl__enslave(slave, bi);
	nl_req_init(&q, RTM_NEWLINK, NLM_F_ACK, sizeof(struct ifinfomsg));
	q.m.i.ifi_index = si;
	nl__a32(&q, IFLA_MASTER, 0);
	if ((r = nl_nl(&q, NULL, NULL)) < 0) return nl_fail(r, "cannot release %s: %s", slave, strerror(-r));
	return 0;
}
int netman_nl_bond_show(const netman_ent *e, FILE *f)
{
	netman_nl_info i;
	char m[NETMAN_NL_MEMBERS * 2][16];
	int n, k, r = netman_nl_getinfo(e->name, &i);
	if (r < 0) return r;
	fprintf(f, "%s %s: mode %s miimon %d", e->name, nl__is(e, "team") ? "team (bonding)" : "bond", i.mode >= 0 && i.mode < 7 ? nl__bmodes[i.mode] : "?", i.miimon);
	if (i.mode == 4) fprintf(f, " lacp_rate %s", i.lacp ? "fast" : "slow");
	if (i.hash >= 0 && i.hash < 6) fprintf(f, " hash %s", nl__bhash[i.hash]);
	if (i.primary > 0) {
		char b[IF_NAMESIZE];
		fprintf(f, " primary %s", if_indextoname(i.primary, b) ? b : "?");
	}
	fprintf(f, "\n  slaves:");
	n = netman_nl_members(e->name, m, NETMAN_NL_MEMBERS * 2);
	for (k = 0; k < n; k++) fprintf(f, " %s", m[k]);
	fprintf(f, "%s\n", n ? "" : " (none)");
	return 0;
}
int netman_nl_team_add(const netman_ent *e) { return netman_nl_bond_add(e); }
int netman_nl_team_del(const netman_ent *e) { return netman_nl_bond_del(e); }
int netman_nl_team_show(const netman_ent *e, FILE *f) { return netman_nl_bond_show(e, f); }
