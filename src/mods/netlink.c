/* netlink.c - see netlink.h. The core of the link modules: spec profiles (parse/format/store), the netlink helpers and the kind dispatch;
 * the modules themselves are nl_bond.c nl_bridge.c nl_vlan.c nl_route.c nl_link.c nl_dot1x.c; the private helpers are netlink_priv.h. */
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
int nl__icmp_probe(const char *ifn, const char *target, int timeout_ms);
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

pid_t nl__readpid(const char *path)
{
	char b[32];
	return nl_slurp(path, b, sizeof b) > 0 ? (pid_t)atoi(b) : 0;
}
void nl__stop(const char *pidfile)
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
const char *const nl__bmodes[] = {"balance-rr", "active-backup", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb"};
const char *const nl__bhash[] = {"layer2", "layer3+4", "layer2+3", "encap2+3", "encap3+4", "vlan+srcmac"};

int nl__bond_mode(const netman_ent *e)
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
int (*netman_nl_kind_ok)(const char *kind);
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
			if (es[i].kind[0] && nl__rank(es[i].kind) == rank && (!netman_nl_kind_ok || netman_nl_kind_ok(es[i].kind))) {
				int r = netman_nl_add(&es[i]);
				if (r < 0 && r != -EEXIST) {
					fprintf(stderr, "netman: %s: %s\n", names[i], r == -EINVAL ? netman_nl_error() : strerror(-r));
					bad++;
				}
			}
	return bad;
}

/* ======================================================================== netlink helpers */
int nl__nest(nl_req *q, int type)
{
	int off = NLMSG_ALIGN(q->h.nlmsg_len);
	nl_attr(q, type, NULL, 0);
	return off;
}
void nl__end(nl_req *q, int off) { ((struct rtattr *)((char *)q + off))->rta_len = q->h.nlmsg_len - off; }

int nl__begin(nl_req *q, const char *name, const char *kind, int parent, int mtu)
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
int nl__dellink(const char *name)
{
	nl_req q;
	nl_req_init(&q, RTM_DELLINK, NLM_F_ACK, sizeof(struct ifinfomsg));
	nl__astr(&q, IFLA_IFNAME, name);
	return nl_nl(&q, NULL, NULL);
}
int nl__setmtu(const char *ifn, int mtu)
{
	nl_req q;
	int i = nl_idx(ifn);
	if (i < 0) return i;
	nl_req_init(&q, RTM_NEWLINK, NLM_F_ACK, sizeof(struct ifinfomsg));
	q.m.i.ifi_index = i;
	nl__a32(&q, IFLA_MTU, mtu);
	return nl_nl(&q, NULL, NULL);
}
int nl__enslave(const char *slave, int master)
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
void nl__rta(struct rtattr **tb, int max, struct rtattr *r, int len)
{
	memset(tb, 0, sizeof(*tb) * (max + 1));
	for (; RTA_OK(r, len); r = RTA_NEXT(r, len))
		if (r->rta_type <= max) tb[r->rta_type] = r;
}
uint32_t nl__u(struct rtattr *a)
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

