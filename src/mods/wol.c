/* wol.c - Wake-on-LAN: the NIC wake modes (ethtool ioctl, letters p u m b a g s, d = off) and the magic packet sent as a UDP
 * broadcast to port 9. Plain C; shares the spec type and error text with netlink.c. */
#define _GNU_SOURCE
#include "netlink.h"
#include "netlink_priv.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ethtool.h>

static unsigned nl__wol_flags(const char *s)
{
	unsigned w = 0;
	for (; *s; s++)
		switch (*s) {
		case 'p': w |= WAKE_PHY; break;
		case 'u': w |= WAKE_UCAST; break;
		case 'm': w |= WAKE_MCAST; break;
		case 'b': w |= WAKE_BCAST; break;
		case 'a': w |= WAKE_ARP; break;
		case 'g': w |= WAKE_MAGIC; break;
		case 's': w |= WAKE_MAGICSECURE; break;
		}
	return w;
}
static void nl__wol_str(unsigned w, char *o)
{
	static const struct { unsigned f; char c; } t[] = {{WAKE_PHY, 'p'}, {WAKE_UCAST, 'u'}, {WAKE_MCAST, 'm'}, {WAKE_BCAST, 'b'}, {WAKE_ARP, 'a'}, {WAKE_MAGIC, 'g'}, {WAKE_MAGICSECURE, 's'}};
	size_t i;
	int n = 0;
	for (i = 0; i < sizeof t / sizeof *t; i++)
		if (w & t[i].f) o[n++] = t[i].c;
	if (!n) o[n++] = 'd';
	o[n] = 0;
}
int netman_nl_wol_add(const netman_ent *e)
{
	struct ethtool_wolinfo w = {.cmd = ETHTOOL_GWOL};
	int r;
	if ((r = netman_nl_check(e)) < 0) return r;
	if (!e->wol[0]) return NL_FAIL("wol needs wol=<letters>");
	if ((r = nl_ethtool(e->name, &w)) < 0) return nl_fail(r, "wake-on-lan on %s: %s", e->name, r == -EOPNOTSUPP ? "driver does not support it" : strerror(-r));
	w.cmd = ETHTOOL_SWOL;
	w.wolopts = nl__wol_flags(e->wol);
	if (w.wolopts & ~w.supported) return nl_fail(-EOPNOTSUPP, "%s supports only wake modes 0x%x", e->name, w.supported);
	if ((r = nl_ethtool(e->name, &w)) < 0) return nl_fail(r, "wake-on-lan on %s: %s", e->name, strerror(-r));
	return 0;
}
int netman_nl_wol_del(const netman_ent *e)
{
	struct ethtool_wolinfo w = {.cmd = ETHTOOL_SWOL, .wolopts = 0};
	return nl_ethtool(e->name, &w);
}
int netman_nl_wol_show(const netman_ent *e, FILE *f)
{
	struct ethtool_wolinfo w = {.cmd = ETHTOOL_GWOL};
	char a[16], b[16];
	int r = nl_ethtool(e->name, &w);
	if (r < 0) return r;
	nl__wol_str(w.supported, a);
	nl__wol_str(w.wolopts, b);
	fprintf(f, "%s wake-on-lan supports %s, set %s\n", e->name, a, b);
	return 0;
}
int netman_nl_wol_packet(const unsigned char mac[6], unsigned char out[102])
{
	int i;
	memset(out, 0xff, 6);
	for (i = 0; i < 16; i++) memcpy(out + 6 + 6 * i, mac, 6);
	return 102;
}
int netman_nl_wol_send(const char *ifn, const char *macs)
{
	unsigned m[6];
	unsigned char mac[6], pkt[102];
	struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(9)};
	int fd, one = 1, i, r = 0;
	if (sscanf(macs, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) return NL_FAIL("bad MAC '%s'", macs);
	for (i = 0; i < 6; i++) mac[i] = (unsigned char)m[i];
	netman_nl_wol_packet(mac, pkt);
	to.sin_addr.s_addr = htonl(INADDR_BROADCAST);
	if ((fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)) < 0) return -errno;
	setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof one);
	if (ifn && *ifn && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifn, strlen(ifn) + 1) < 0) r = -errno;
	if (!r && sendto(fd, pkt, sizeof pkt, 0, (struct sockaddr *)&to, sizeof to) < 0) r = -errno;
	close(fd);
	return r;
}
