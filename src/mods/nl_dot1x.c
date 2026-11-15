/* nl_dot1x.c - wired 802.1X (one wpa_supplicant per interface). Part of the link modules (netlink.h); shared helpers: netlink_priv.h. */
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
