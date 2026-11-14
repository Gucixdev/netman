/* netlink.c - see netlink.h. Links, bonding/team, bridge, vlan, macvlan/ipvlan, veth, dummy, routes, rules,
 * ECMP, link settings, Wake-on-LAN, IPv6, wired 802.1X, spec profiles, and the private helpers of netlink_priv.h. */
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

const char *netman_nl_sys = "/sys";
const char *netman_nl_proc = "/proc";
const char *netman_nl_rt_tables = "/etc/iproute2/rt_tables";
static int nl__icmp_probe(const char *ifn, const char *target, int timeout_ms);
int (*netman_nl_probe_fn)(const char *, const char *, int) = nl__icmp_probe;

/* ======================================================================== shared helpers (netlink_priv.h) */
static char nl__err[256];
const char *netman_nl_error(void) { return nl__err; }
int nl_fail(int e, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(nl__err, sizeof nl__err, fmt, ap);
	va_end(ap);
	return e < 0 ? e : -e;
}
void nl_cpy(char *d, size_t n, const char *s)
{
	size_t k = s ? strlen(s) : 0;
	if (!n) return;
	if (k >= n) k = n - 1;
	if (k) memcpy(d, s, k);
	d[k] = 0;
}
int nl_safe_name(const char *s, size_t max)
{
	size_t i, n = s ? strlen(s) : 0;
	if (!n || n >= max || s[0] == '.') return 0;
	for (i = 0; i < n; i++)
		if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '_' || s[i] == '-' || s[i] == '.')) return 0;
	return 1;
}
char *nl_trim(char *s)
{
	char *e;
	while (*s == ' ' || *s == '\t') s++;
	e = s + strlen(s);
	while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\n' || e[-1] == '\r')) *--e = 0;
	return s;
}
long nl_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}
int nl_mkdirs(const char *p)
{
	char t[512], *s;
	if (strlen(p) >= sizeof t) return -ENAMETOOLONG;
	strcpy(t, p);
	for (s = t + 1; *s; s++)
		if (*s == '/') {
			*s = 0;
			if (mkdir(t, 0755) < 0 && errno != EEXIST) return -errno;
			*s = '/';
		}
	return (mkdir(t, 0755) < 0 && errno != EEXIST) ? -errno : 0;
}
int nl_write_atomic(const char *path, const char *data, size_t len, mode_t mode)
{
	char t[600];
	int fd;
	size_t off = 0;
	if (snprintf(t, sizeof t, "%s.XXXXXX", path) >= (int)sizeof t) return -ENAMETOOLONG;
	if ((fd = mkstemp(t)) < 0) return -errno;
	while (off < len) {
		ssize_t w = write(fd, data + off, len - off);
		if (w < 0) {
			if (errno == EINTR) continue;
			goto fail;
		}
		off += w;
	}
	if (fchmod(fd, mode) < 0 || fsync(fd) < 0) goto fail;
	close(fd);
	if (rename(t, path) < 0) {
		unlink(t);
		return -errno;
	}
	return 0;
fail : {
	int e = errno;
	close(fd);
	unlink(t);
	return -e;
}
}
int nl_slurp(const char *path, char *buf, size_t n)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t r;
	if (fd < 0) return -errno;
	r = read(fd, buf, n - 1);
	close(fd);
	if (r < 0) return -errno;
	buf[r] = 0;
	return (int)r;
}
void nl_put(struct nl_out *o, const char *fmt, ...)
{
	va_list ap;
	int k;
	va_start(ap, fmt);
	k = vsnprintf(o->p + o->n, o->n < o->cap ? o->cap - o->n : 0, fmt, ap);
	va_end(ap);
	if (k > 0) o->n += k;
}
int nl_exec(char *const argv[], const char *input, char *err, size_t errn)
{
	int in[2] = {-1, -1}, ou[2] = {-1, -1}, st;
	pid_t p;
	if (err && errn) err[0] = 0;
	if (pipe(in) < 0 || pipe(ou) < 0) return -errno;
	if ((p = fork()) < 0) return -errno;
	if (!p) {
		dup2(in[0], 0);
		dup2(ou[1], 2);
		dup2(ou[1], 1);
		close(in[0]), close(in[1]), close(ou[0]), close(ou[1]);
		execvp(argv[0], argv);
		_exit(127);
	}
	close(in[0]);
	close(ou[1]);
	if (input) {
		size_t n = strlen(input), off = 0;
		signal(SIGPIPE, SIG_IGN);
		while (off < n) {
			ssize_t w = write(in[1], input + off, n - off);
			if (w < 0 && errno == EINTR) continue;
			if (w <= 0) break;
			off += w;
		}
	}
	close(in[1]);
	{
		size_t got = 0;
		char tmp[256];
		ssize_t k;
		while ((k = read(ou[0], tmp, sizeof tmp)) > 0)
			if (err && got + 1 < errn) {
				size_t c = (size_t)k < errn - got - 1 ? (size_t)k : errn - got - 1;
				memcpy(err + got, tmp, c);
				got += c;
				err[got] = 0;
			}
	}
	close(ou[0]);
	while (waitpid(p, &st, 0) < 0)
		if (errno != EINTR) return -errno;
	if (WIFEXITED(st) && WEXITSTATUS(st) == 127) return -ENOENT;
	return WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 0 : -EIO;
}
int nl_parse_ip(const char *s, nl_ip *o, int need_plen)
{
	char t[64], *sl;
	if (!s || !*s || strlen(s) >= sizeof t) return -EINVAL;
	strcpy(t, s);
	o->plen = -1;
	if ((sl = strchr(t, '/'))) {
		char *e;
		long v;
		*sl++ = 0;
		v = strtol(sl, &e, 10);
		if (!*sl || *e || v < 0 || v > 128) return -EINVAL;
		o->plen = (int)v;
	}
	if (need_plen && o->plen < 0) return -EINVAL;
	memset(o->b, 0, 16);
	if (inet_pton(AF_INET, t, o->b) == 1) o->fam = AF_INET;
	else if (inet_pton(AF_INET6, t, o->b) == 1) o->fam = AF_INET6;
	else return -EINVAL;
	if (o->plen > (o->fam == AF_INET ? 32 : 128)) return -EINVAL;
	return 0;
}
int nl_iplen(const nl_ip *i) { return i->fam == AF_INET ? 4 : 16; }
void nl_req_init(nl_req *q, int type, int flags, size_t msglen)
{
	memset(q, 0, sizeof *q);
	q->h.nlmsg_type = type;
	q->h.nlmsg_flags = NLM_F_REQUEST | flags;
	q->h.nlmsg_len = NLMSG_LENGTH(msglen);
}
void nl_attr(nl_req *q, int type, const void *d, int len)
{
	struct rtattr *a = (struct rtattr *)((char *)q + NLMSG_ALIGN(q->h.nlmsg_len));
	if (NLMSG_ALIGN(q->h.nlmsg_len) + RTA_SPACE(len) > sizeof *q) return; /* specs are small: cannot happen */
	a->rta_type = type;
	a->rta_len = RTA_LENGTH(len);
	if (len) memcpy(RTA_DATA(a), d, len);
	q->h.nlmsg_len = NLMSG_ALIGN(q->h.nlmsg_len) + RTA_ALIGN(a->rta_len);
}
int nl_nl(nl_req *q, nl_cb cb, void *u)
{
	struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
	struct timeval tv = {5, 0};
	static char buf[65536];
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE), r = 0;
	if (fd < 0) return -errno;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	q->h.nlmsg_seq = 1;
	if (sendto(fd, q, q->h.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof sa) < 0) {
		r = -errno;
		close(fd);
		return r;
	}
	for (;;) {
		ssize_t n = recv(fd, buf, sizeof buf, 0);
		struct nlmsghdr *m = (struct nlmsghdr *)buf;
		if (n < 0) {
			if (errno == EINTR) continue;
			r = -errno;
			break;
		}
		for (; NLMSG_OK(m, (size_t)n); m = NLMSG_NEXT(m, n)) {
			if (m->nlmsg_type == NLMSG_DONE) goto out;
			if (m->nlmsg_type == NLMSG_ERROR) {
				r = ((struct nlmsgerr *)NLMSG_DATA(m))->error;
				goto out;
			}
			if (cb) cb(m, u);
		}
	}
out:
	close(fd);
	return r;
}
int nl_idx(const char *ifn)
{
	unsigned i = ifn && *ifn ? if_nametoindex(ifn) : 0;
	return i ? (int)i : -ENODEV;
}

static int nl__nm(const char *s) { return nl_safe_name(s, 16); }
static int nl__is(const netman_ent *e, const char *k) { return !strcmp(e->kind, k); }
static pid_t nl__readpid(const char *path)
{
	char b[32];
	return nl_slurp(path, b, sizeof b) > 0 ? (pid_t)atoi(b) : 0;
}
static void nl__stop(const char *pidfile)
{
	pid_t p = nl__readpid(pidfile);
	if (p > 1) kill(p, SIGTERM);
	unlink(pidfile);
}

/* ======================================================================== spec: keys, parse, format */
#define KS(k, f) {k, 's', offsetof(netman_ent, f), sizeof(((netman_ent *)0)->f)}
#define KI(k, f) {k, 'i', offsetof(netman_ent, f), 0}
#define KT(k, f) {k, 't', offsetof(netman_ent, f), 0}
static const struct {
	const char *k;
	char t;
	size_t off, sz;
} nl__keys[] = {
	KS("kind", kind), KS("name", name), KS("iface", name), KS("parent", parent), KS("peer", peer), KS("inner", inner),
	KS("mode", mode), KS("primary", primary), KS("lacp_rate", lacp_rate), KS("xmit_hash_policy", hash), KS("runner", runner),
	KI("miimon", miimon), KT("stp", stp), KI("forward_delay", fwd_delay), KT("vlan_filtering", vlan_filtering), KI("vid", vid),
	KI("inner_vid", inner_vid), KI("mtu", mtu), KI("netns_pid", netns_pid), KS("proto", proto),
	KS("address", addr), KS("gateway", gateway), KS("dns", dns),
	KI("table", table), KI("metric", metric), KS("dst", dst), KS("src", src), KS("rtype", rtype),
	KS("from", from), KS("to", to), KS("iif", iif), KS("oif", oif), KI("fwmark", fwmark), KI("prio", prio),
	KI("probe_ms", probe_ms), KI("fail_after", fail_after), KI("ok_after", ok_after),
	KS("upstream", upstream), KS("btmac", btmac), KS("dhcp_start", dhcp_start), KS("dhcp_end", dhcp_end),
	KS("eap", eap), KS("identity", identity), KS("anon_identity", anon_identity), KS("password", password),
	KS("ca_cert", ca_cert), KS("client_cert", client_cert), KS("private_key", private_key), KS("phase2", phase2),
	KT("tso", tso), KT("gso", gso), KT("gro", gro), KT("sg", sg), KT("rxcsum", rxcsum), KT("txcsum", txcsum),
	KI("speed", speed), KT("autoneg", autoneg), KS("duplex", duplex), KS("wol", wol),
	KT("accept_ra", accept_ra), KT("autoconf", autoconf), KT("tempaddr", tempaddr), KT("forwarding", forwarding),
	KS("pd_prefix", pd_prefix),
};
#define NL_NKEYS (sizeof nl__keys / sizeof nl__keys[0])

void netman_nl_init(netman_ent *e)
{
	size_t i;
	memset(e, 0, sizeof *e);
	for (i = 0; i < NL_NKEYS; i++)
		if (nl__keys[i].t == 't') *(int *)((char *)e + nl__keys[i].off) = -1;
}
static int nl__int(const char *v, int *o)
{
	char *end;
	long n;
	if (!strcmp(v, "yes") || !strcmp(v, "true") || !strcmp(v, "on")) return *o = 1, 0;
	if (!strcmp(v, "no") || !strcmp(v, "false") || !strcmp(v, "off")) return *o = 0, 0;
	n = strtol(v, &end, 0);
	if (!*v || *end || n < -2147483647L || n > 2147483647L) return -EINVAL;
	*o = (int)n;
	return 0;
}
int netman_nl_parse(const char *text, netman_ent *e)
{
	char *buf = strdup(text), *l, *save;
	int rc = 0;
	if (!buf) return -ENOMEM;
	netman_nl_init(e);
	for (l = strtok_r(buf, "\n", &save); l && !rc; l = strtok_r(NULL, "\n", &save)) {
		char *k = nl_trim(l), *v;
		size_t i;
		if (!*k || *k == '#') continue;
		if (!(v = strchr(k, '='))) { rc = NL_FAIL("line without '=': %s", k); break; }
		*v++ = 0;
		k = nl_trim(k), v = nl_trim(v);
		if (!strcmp(k, "member")) {
			if (e->nmember >= NETMAN_NL_MEMBERS || !nl__nm(v)) rc = NL_FAIL("bad member '%s'", v);
			else nl_cpy(e->member[e->nmember++], 16, v);
			continue;
		}
		if (!strcmp(k, "vlan")) { /* vlan = 10[,pvid][,untagged] */
			char *s2, *t = strtok_r(v, ", ", &s2);
			netman_nl_vlan *vl = &e->vlan[e->nvlan < NETMAN_NL_VLANS ? e->nvlan : 0];
			if (e->nvlan >= NETMAN_NL_VLANS || !t || (vl->vid = atoi(t)) < 1 || vl->vid > 4094) { rc = NL_FAIL("bad vlan '%s'", v); continue; }
			for (t = strtok_r(NULL, ", ", &s2); t; t = strtok_r(NULL, ", ", &s2))
				if (!strcmp(t, "pvid")) vl->pvid = 1;
				else if (!strcmp(t, "untagged")) vl->untagged = 1;
				else rc = NL_FAIL("bad vlan flag '%s'", t);
			e->nvlan++;
			continue;
		}
		if (!strcmp(k, "uplink")) { /* uplink = IF,GATEWAY[,PROBE[,WEIGHT]] */
			char *f[4] = {0}, *s2, *t;
			int n = 0;
			netman_nl_uplink *u = &e->up[e->nup < NETMAN_NL_UPLINKS ? e->nup : 0];
			for (t = strtok_r(v, ",", &s2); t && n < 4; t = strtok_r(NULL, ",", &s2)) f[n++] = nl_trim(t);
			if (e->nup >= NETMAN_NL_UPLINKS || n < 2 || !nl__nm(f[0])) { rc = NL_FAIL("bad uplink '%s'", v); continue; }
			nl_cpy(u->ifn, 16, f[0]);
			nl_cpy(u->gw, 46, f[1]);
			if (n > 2) nl_cpy(u->probe, 46, f[2]);
			u->weight = n > 3 ? atoi(f[3]) : 1;
			u->up = 1;
			e->nup++;
			continue;
		}
		for (i = 0; i < NL_NKEYS; i++)
			if (!strcmp(k, nl__keys[i].k)) break;
		if (i == NL_NKEYS) { rc = NL_FAIL("unknown key '%s'", k); break; }
		if (nl__keys[i].t == 's') {
			if (strlen(v) >= nl__keys[i].sz) rc = NL_FAIL("%s too long", k);
			else strcpy((char *)e + nl__keys[i].off, v);
		} else if (nl__int(v, (int *)((char *)e + nl__keys[i].off)) < 0) rc = NL_FAIL("bad number for %s: '%s'", k, v);
	}
	free(buf);
	return rc ? rc : netman_nl_check(e);
}
int netman_nl_format(const netman_ent *e, char *out, size_t cap)
{
	size_t i, o = 0;
	int j;
#define P(...)                                                                          \
	do {                                                                            \
		int n_ = snprintf(out + o, o < cap ? cap - o : 0, __VA_ARGS__);         \
		if (n_ < 0) return -EIO;                                                \
		o += n_;                                                                \
	} while (0)
	P("kind=%s\n", e->kind);
	for (i = 0; i < NL_NKEYS; i++) {
		const char *p = (const char *)e + nl__keys[i].off;
		if (!strcmp(nl__keys[i].k, "kind") || !strcmp(nl__keys[i].k, "iface")) continue;
		if (nl__keys[i].t == 's') {
			if (*p) P("%s=%s\n", nl__keys[i].k, p);
		} else if (nl__keys[i].t == 't') {
			if (*(const int *)p != -1) P("%s=%d\n", nl__keys[i].k, *(const int *)p);
		} else if (*(const int *)p) P("%s=%d\n", nl__keys[i].k, *(const int *)p);
	}
	for (j = 0; j < e->nmember; j++) P("member=%s\n", e->member[j]);
	for (j = 0; j < e->nvlan; j++) P("vlan=%d%s%s\n", e->vlan[j].vid, e->vlan[j].pvid ? ",pvid" : "", e->vlan[j].untagged ? ",untagged" : "");
	for (j = 0; j < e->nup; j++) P("uplink=%s,%s,%s,%d\n", e->up[j].ifn, e->up[j].gw, e->up[j].probe, e->up[j].weight ? e->up[j].weight : 1);
#undef P
	return o >= cap ? -E2BIG : (int)o;
}

static const char *const nl__kinds[] = {"bond", "team", "bridge", "vlan", "macvlan", "ipvlan", "veth", "dummy", "tether", "dot1x", "route", "rule", "ecmp", "link", "ipv6", "wol", NULL};
static const char *const nl__bmodes[] = {"balance-rr", "active-backup", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb"};
static const char *const nl__bhash[] = {"layer2", "layer3+4", "layer2+3", "encap2+3", "encap3+4", "vlan+srcmac"};

static int nl__bond_mode(const netman_ent *e)
{
	static const struct { const char *r, *m; } team[] = {{"activebackup", "active-backup"}, {"lacp", "802.3ad"}, {"loadbalance", "balance-xor"}, {"broadcast", "broadcast"}, {"roundrobin", "balance-rr"}};
	const char *m = e->mode;
	size_t i;
	if (nl__is(e, "team") && e->runner[0])
		for (i = 0; i < 5; i++)
			if (!strcmp(e->runner, team[i].r)) m = team[i].m;
	if (!*m) return 1; /* active-backup */
	if (!strcmp(m, "lacp")) m = "802.3ad";
	for (i = 0; i < 7; i++)
		if (!strcmp(m, nl__bmodes[i]) || (m[0] >= '0' && m[0] <= '6' && !m[1] && m[0] - '0' == (int)i)) return (int)i;
	return -1;
}
int netman_nl_check(const netman_ent *e)
{
	int i;
	for (i = 0; nl__kinds[i]; i++)
		if (nl__is(e, nl__kinds[i])) break;
	if (!nl__kinds[i]) return NL_FAIL("unknown kind '%s'", e->kind);
	if (!nl__nm(e->name)) return NL_FAIL("bad or missing name");
	if ((nl__is(e, "bond") || nl__is(e, "team")) && nl__bond_mode(e) < 0) return NL_FAIL("bad bond mode '%s'", e->mode);
	if (e->hash[0]) {
		for (i = 0; i < 6 && strcmp(e->hash, nl__bhash[i]); i++) ;
		if (i == 6) return NL_FAIL("bad xmit_hash_policy '%s'", e->hash);
	}
	if (e->lacp_rate[0] && strcmp(e->lacp_rate, "slow") && strcmp(e->lacp_rate, "fast")) return NL_FAIL("lacp_rate must be slow or fast");
	for (i = 0; i < e->nmember; i++)
		if (!nl__nm(e->member[i])) return NL_FAIL("bad member name");
	if (e->vid && (e->vid < 1 || e->vid > 4094)) return NL_FAIL("vlan id must be 1..4094");
	if (e->proto[0] && strcmp(e->proto, "802.1q") && strcmp(e->proto, "802.1ad")) return NL_FAIL("proto must be 802.1q or 802.1ad");
	for (i = 0; i < e->nup; i++)
		if (!nl__nm(e->up[i].ifn) || e->up[i].weight < 0 || e->up[i].weight > 255) return NL_FAIL("bad uplink %d", i);
	if (e->wol[0] && strspn(e->wol, "pumbagsd") != strlen(e->wol)) return NL_FAIL("wol letters are p u m b a g s d");
	if (nl__is(e, "dot1x")) { /* the strings land in a quoted wpa_supplicant config: no quotes, backslashes, newlines */
		const char *s[] = {e->identity, e->anon_identity, e->password, e->ca_cert, e->client_cert, e->private_key, e->phase2, e->eap};
		for (i = 0; i < 8; i++)
			if (strpbrk(s[i], "\"\\\r\n")) return NL_FAIL("dot1x fields may not contain quotes, backslashes or newlines");
	}
	return 0;
}

static int nl__path(char *p, size_t n, const char *name, const char *ext)
{
	if (!nl_safe_name(name, 64)) return nl_fail(-EINVAL, "bad profile name");
	snprintf(p, n, "%s/%s.%s", netman_conf_dir, name, ext);
	return 0;
}
int netman_nl_load(const char *name, netman_ent *e)
{
	char path[600], buf[8192];
	int r = nl__path(path, sizeof path, name, "ent");
	if (r < 0) return r;
	if ((r = nl_slurp(path, buf, sizeof buf)) < 0) return nl_fail(r, "cannot read %s: %s", path, strerror(-r));
	if (!(r = netman_nl_parse(buf, e)) && !e->name[0]) nl_cpy(e->name, 16, name);
	return r;
}
int netman_nl_save(const netman_ent *e)
{
	char path[600], b[8192];
	int n = netman_nl_format(e, b, sizeof b), r;
	if (n < 0) return n;
	if ((r = netman_nl_check(e)) < 0) return r;
	if ((r = nl_mkdirs(netman_conf_dir)) < 0) return r;
	if ((r = nl__path(path, sizeof path, e->name, "ent")) < 0) return r;
	return nl_write_atomic(path, b, n, nl__is(e, "dot1x") ? 0600 : 0644);
}
int netman_nl_list(char names[][64], int max)
{
	struct dirent **ls = NULL;
	int n = scandir(netman_conf_dir, &ls, NULL, alphasort), i, c = 0;
	if (n < 0) return errno == ENOENT ? 0 : -errno;
	for (i = 0; i < n; i++) {
		size_t l = strlen(ls[i]->d_name);
		if (c < max && l > 4 && !strcmp(ls[i]->d_name + l - 4, ".ent") && l - 4 < 64) {
			memcpy(names[c], ls[i]->d_name, l - 4);
			names[c++][l - 4] = 0;
		}
		free(ls[i]);
	}
	free(ls);
	return c;
}
static int nl__rank(const char *k)
{
	static const char *const r[] = {"dummy veth", "bond team", "bridge", "vlan macvlan ipvlan", "link ipv6 wol", "route rule ecmp", "tether dot1x"};
	int i;
	for (i = 0; i < 7; i++) {
		const char *p = strstr(r[i], k);
		if (p && (p == r[i] || p[-1] == ' ') && (!p[strlen(k)] || p[strlen(k)] == ' ')) return i;
	}
	return 9;
}
int netman_nl_apply_all(void)
{
	char names[64][64];
	static netman_ent es[64];
	int n = netman_nl_list(names, 64), i, rank, bad = 0;
	if (n < 0) return n;
	for (i = 0; i < n; i++)
		if (netman_nl_load(names[i], &es[i]) < 0) {
			fprintf(stderr, "netman: %s: %s\n", names[i], netman_nl_error());
			es[i].kind[0] = 0;
			bad++;
		}
	for (rank = 0; rank < 8; rank++)
		for (i = 0; i < n; i++)
			if (es[i].kind[0] && nl__rank(es[i].kind) == rank) {
				int r = netman_nl_add(&es[i]);
				if (r < 0 && r != -EEXIST) {
					fprintf(stderr, "netman: %s: %s\n", names[i], r == -EINVAL ? netman_nl_error() : strerror(-r));
					bad++;
				}
			}
	return bad;
}

/* ======================================================================== netlink helpers */
static void nl__a8(nl_req *q, int t, uint8_t v) { nl_attr(q, t, &v, 1); }
static void nl__a16(nl_req *q, int t, uint16_t v) { nl_attr(q, t, &v, 2); }
static void nl__a32(nl_req *q, int t, uint32_t v) { nl_attr(q, t, &v, 4); }
static void nl__astr(nl_req *q, int t, const char *s) { nl_attr(q, t, s, (int)strlen(s) + 1); }
static int nl__nest(nl_req *q, int type)
{
	int off = NLMSG_ALIGN(q->h.nlmsg_len);
	nl_attr(q, type, NULL, 0);
	return off;
}
static void nl__end(nl_req *q, int off) { ((struct rtattr *)((char *)q + off))->rta_len = q->h.nlmsg_len - off; }

static int nl__begin(nl_req *q, const char *name, const char *kind, int parent, int mtu)
{
	int li;
	nl_req_init(q, RTM_NEWLINK, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, sizeof(struct ifinfomsg));
	nl__astr(q, IFLA_IFNAME, name);
	if (parent > 0) nl__a32(q, IFLA_LINK, parent);
	if (mtu > 0) nl__a32(q, IFLA_MTU, mtu);
	li = nl__nest(q, IFLA_LINKINFO);
	nl__astr(q, IFLA_INFO_KIND, kind);
	return li;
}
static int nl__dellink(const char *name)
{
	nl_req q;
	nl_req_init(&q, RTM_DELLINK, NLM_F_ACK, sizeof(struct ifinfomsg));
	nl__astr(&q, IFLA_IFNAME, name);
	return nl_nl(&q, NULL, NULL);
}
static int nl__setmtu(const char *ifn, int mtu)
{
	nl_req q;
	int i = nl_idx(ifn);
	if (i < 0) return i;
	nl_req_init(&q, RTM_NEWLINK, NLM_F_ACK, sizeof(struct ifinfomsg));
	q.m.i.ifi_index = i;
	nl__a32(&q, IFLA_MTU, mtu);
	return nl_nl(&q, NULL, NULL);
}
static int nl__enslave(const char *slave, int master)
{
	nl_req q;
	int i = nl_idx(slave), r;
	if (i < 0) return nl_fail(i, "no such interface '%s'", slave);
	netman_link_set(slave, 0); /* bonding refuses a slave that is up */
	nl_req_init(&q, RTM_NEWLINK, NLM_F_ACK, sizeof(struct ifinfomsg));
	q.m.i.ifi_index = i;
	nl__a32(&q, IFLA_MASTER, master);
	if ((r = nl_nl(&q, NULL, NULL)) < 0) return nl_fail(r, "cannot enslave %s: %s", slave, strerror(-r));
	return netman_link_set(slave, 1);
}
static void nl__rta(struct rtattr **tb, int max, struct rtattr *r, int len)
{
	memset(tb, 0, sizeof(*tb) * (max + 1));
	for (; RTA_OK(r, len); r = RTA_NEXT(r, len))
		if (r->rta_type <= max) tb[r->rta_type] = r;
}
static uint32_t nl__u(struct rtattr *a)
{
	if (!a) return (uint32_t)-1;
	switch (RTA_PAYLOAD(a)) {
	case 1: return *(uint8_t *)RTA_DATA(a);
	case 2: return *(uint16_t *)RTA_DATA(a);
	default: return *(uint32_t *)RTA_DATA(a);
	}
}

/* ---------- link queries ---------- */
static void nl__info_cb(const struct nlmsghdr *m, void *u)
{
	netman_nl_info *o = u;
	struct ifinfomsg *i = NLMSG_DATA(m);
	struct rtattr *tb[64], *li[16], *d[64];
	if (m->nlmsg_type != RTM_NEWLINK) return;
	nl__rta(tb, 63, IFLA_RTA(i), IFLA_PAYLOAD(m));
	o->idx = i->ifi_index;
	o->up = !!(i->ifi_flags & IFF_UP);
	o->master = tb[IFLA_MASTER] ? (int)nl__u(tb[IFLA_MASTER]) : 0;
	o->link = tb[IFLA_LINK] ? (int)nl__u(tb[IFLA_LINK]) : 0;
	o->mtu = tb[IFLA_MTU] ? (int)nl__u(tb[IFLA_MTU]) : 0;
	if (!tb[IFLA_LINKINFO]) return;
	nl__rta(li, 15, RTA_DATA(tb[IFLA_LINKINFO]), RTA_PAYLOAD(tb[IFLA_LINKINFO]));
	if (li[IFLA_INFO_KIND]) nl_cpy(o->kind, sizeof o->kind, RTA_DATA(li[IFLA_INFO_KIND]));
	if (!li[IFLA_INFO_DATA]) return;
	nl__rta(d, 63, RTA_DATA(li[IFLA_INFO_DATA]), RTA_PAYLOAD(li[IFLA_INFO_DATA]));
	if (!strcmp(o->kind, "bond")) {
		o->mode = (int)nl__u(d[IFLA_BOND_MODE]);
		o->miimon = (int)nl__u(d[IFLA_BOND_MIIMON]);
		o->lacp = (int)nl__u(d[IFLA_BOND_AD_LACP_RATE]);
		o->hash = (int)nl__u(d[IFLA_BOND_XMIT_HASH_POLICY]);
		o->primary = (int)nl__u(d[IFLA_BOND_PRIMARY]);
	} else if (!strcmp(o->kind, "bridge")) {
		o->stp = (int)nl__u(d[IFLA_BR_STP_STATE]);
		o->fwd_delay = (int)nl__u(d[IFLA_BR_FORWARD_DELAY]);
		o->vlan_filtering = (int)nl__u(d[IFLA_BR_VLAN_FILTERING]);
	} else if (!strcmp(o->kind, "vlan")) {
		o->vid = (int)nl__u(d[IFLA_VLAN_ID]);
		o->proto = d[IFLA_VLAN_PROTOCOL] ? ntohs(*(uint16_t *)RTA_DATA(d[IFLA_VLAN_PROTOCOL])) : 0x8100;
	} else if (!strcmp(o->kind, "macvlan") || !strcmp(o->kind, "ipvlan")) o->mode = (int)nl__u(d[1]); /* IFLA_*VLAN_MODE == 1 */
}
int netman_nl_getinfo(const char *ifn, netman_nl_info *o)
{
	nl_req q;
	int r;
	memset(o, -1, sizeof *o);
	o->kind[0] = 0;
	o->idx = 0;
	nl_req_init(&q, RTM_GETLINK, NLM_F_ACK, sizeof(struct ifinfomsg));
	nl__astr(&q, IFLA_IFNAME, ifn);
	r = nl_nl(&q, nl__info_cb, o);
	if (r < 0) return r;
	return o->idx ? 0 : -ENODEV;
}
struct nl_lk { char name[16]; int idx, master; };
struct nl_lks { struct nl_lk *v; int n, max; };
static void nl__lk_cb(const struct nlmsghdr *m, void *u)
{
	struct nl_lks *l = u;
	struct ifinfomsg *i = NLMSG_DATA(m);
	struct rtattr *tb[64];
	if (m->nlmsg_type != RTM_NEWLINK || l->n >= l->max) return;
	nl__rta(tb, 63, IFLA_RTA(i), IFLA_PAYLOAD(m));
	if (!tb[IFLA_IFNAME]) return;
	nl_cpy(l->v[l->n].name, 16, RTA_DATA(tb[IFLA_IFNAME]));
	l->v[l->n].idx = i->ifi_index;
	l->v[l->n].master = tb[IFLA_MASTER] ? (int)nl__u(tb[IFLA_MASTER]) : 0;
	l->n++;
}
int netman_nl_members(const char *master, char out[][16], int max)
{
	static struct nl_lk v[512];
	struct nl_lks l = {v, 0, 512};
	nl_req q;
	int mi = nl_idx(master), r, i, c = 0;
	if (mi < 0) return mi;
	nl_req_init(&q, RTM_GETLINK, NLM_F_DUMP, sizeof(struct ifinfomsg));
	if ((r = nl_nl(&q, nl__lk_cb, &l)) < 0) return r;
	for (i = 0; i < l.n && c < max; i++)
		if (v[i].master == mi) nl_cpy(out[c++], 16, v[i].name);
	return c;
}

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
static int nl__icmp_probe(const char *ifn, const char *target, int timeout_ms)
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

/* ======================================================================== 802.1X wired */
int netman_nl_dot1x_conf(const netman_ent *e, char *out, size_t cap)
{
	struct nl_out o = {out, 0, cap};
	const char *eap = e->eap[0] ? e->eap : "PEAP";
	int tls = !strcasecmp(eap, "TLS");
	if (cap) out[0] = 0;
	if (!e->identity[0]) return NL_FAIL("dot1x needs identity=");
	if (tls ? (!e->client_cert[0] || !e->private_key[0]) : !e->password[0]) return NL_FAIL(tls ? "EAP-TLS needs client_cert= and private_key=" : "dot1x needs password=");
	nl_put(&o, NL_HDR "ctrl_interface=/run/wpa_supplicant\nap_scan=0\neapol_version=2\nnetwork={\n\tkey_mgmt=IEEE8021X\n\teap=%s\n\teapol_flags=0\n\tidentity=\"%s\"\n", eap, e->identity);
	if (e->anon_identity[0]) nl_put(&o, "\tanonymous_identity=\"%s\"\n", e->anon_identity);
	if (!tls) nl_put(&o, "\tpassword=\"%s\"\n", e->password);
	if (e->ca_cert[0]) nl_put(&o, "\tca_cert=\"%s\"\n", e->ca_cert);
	if (tls) nl_put(&o, "\tclient_cert=\"%s\"\n\tprivate_key=\"%s\"\n", e->client_cert, e->private_key);
	if (e->password[0] && tls) nl_put(&o, "\tprivate_key_passwd=\"%s\"\n", e->password);
	nl_put(&o, !tls && e->phase2[0] ? "\tphase2=\"%s\"\n" : !tls ? "\tphase2=\"%s\"\n" : "%s", !tls && e->phase2[0] ? e->phase2 : !tls ? "auth=MSCHAPV2" : "");
	nl_put(&o, "}\n");
	return o.n >= cap ? -E2BIG : (int)o.n;
}
int netman_nl_dot1x_add(const netman_ent *e)
{
	char conf[1024], path[300], pid[300], err[256];
	char *argv[] = {"wpa_supplicant", "-B", "-D", "wired", "-i", (char *)e->name, "-c", path, "-P", pid, NULL};
	int r;
	if ((r = netman_nl_check(e)) < 0) return r;
	if ((r = netman_nl_dot1x_conf(e, conf, sizeof conf)) < 0) return r;
	if ((r = nl_mkdirs(netman_run_dir)) < 0) return r;
	snprintf(path, sizeof path, "%s/dot1x-%s.conf", netman_run_dir, e->name);
	snprintf(pid, sizeof pid, "%s/dot1x-%s.pid", netman_run_dir, e->name);
	if ((r = nl_write_atomic(path, conf, strlen(conf), 0600)) < 0) return r; /* holds the password: root only */
	netman_link_set(e->name, 1);
	if ((r = nl_exec(argv, NULL, err, sizeof err)) < 0) return nl_fail(r, "wpa_supplicant (optional helper) failed on %s: %s", e->name, r == -ENOENT ? "not installed" : err);
	return 0;
}
int netman_nl_dot1x_del(const netman_ent *e)
{
	char p[300];
	snprintf(p, sizeof p, "%s/dot1x-%s.pid", netman_run_dir, e->name);
	nl__stop(p);
	snprintf(p, sizeof p, "%s/dot1x-%s.conf", netman_run_dir, e->name);
	unlink(p);
	return 0;
}
int netman_nl_dot1x_show(const netman_ent *e, FILE *f)
{
	char p[300];
	pid_t pid;
	snprintf(p, sizeof p, "%s/dot1x-%s.pid", netman_run_dir, e->name);
	pid = nl__readpid(p);
	fprintf(f, "%s 802.1X wired: supplicant %s\n", e->name, pid > 1 && kill(pid, 0) == 0 ? "running" : "not running");
	return 0;
}

/* ======================================================================== dispatch */
#define NL_SWITCH(fn, ...)                                                          \
	do {                                                                         \
		const char *k = e->kind;                                             \
		if (!strcmp(k, "bond")) return netman_nl_bond_##fn(__VA_ARGS__);    \
		if (!strcmp(k, "team")) return netman_nl_team_##fn(__VA_ARGS__);    \
		if (!strcmp(k, "bridge")) return netman_nl_bridge_##fn(__VA_ARGS__);\
		if (!strcmp(k, "vlan")) return netman_nl_vlan_##fn(__VA_ARGS__);    \
		if (!strcmp(k, "macvlan")) return netman_nl_macvlan_##fn(__VA_ARGS__);\
		if (!strcmp(k, "ipvlan")) return netman_nl_ipvlan_##fn(__VA_ARGS__);\
		if (!strcmp(k, "veth")) return netman_nl_veth_##fn(__VA_ARGS__);    \
		if (!strcmp(k, "dummy")) return netman_nl_dummy_##fn(__VA_ARGS__);  \
		if (!strcmp(k, "tether")) return netman_nl_tether_##fn(__VA_ARGS__);\
		if (!strcmp(k, "dot1x")) return netman_nl_dot1x_##fn(__VA_ARGS__);  \
		if (!strcmp(k, "route")) return netman_nl_route_##fn(__VA_ARGS__);  \
		if (!strcmp(k, "rule")) return netman_nl_rule_##fn(__VA_ARGS__);    \
		if (!strcmp(k, "ecmp")) return netman_nl_ecmp_##fn(__VA_ARGS__);    \
		if (!strcmp(k, "link")) return netman_nl_link_##fn(__VA_ARGS__);    \
		if (!strcmp(k, "ipv6")) return netman_nl_ipv6_##fn(__VA_ARGS__);    \
		if (!strcmp(k, "wol")) return netman_nl_wol_##fn(__VA_ARGS__);      \
		return NL_FAIL("unknown kind '%s'", k);                             \
	} while (0)
int netman_nl_add(const netman_ent *e) { NL_SWITCH(add, e); }
int netman_nl_del(const netman_ent *e) { NL_SWITCH(del, e); }
int netman_nl_show(const netman_ent *e, FILE *f) { NL_SWITCH(show, e, f); }
