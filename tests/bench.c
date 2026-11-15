/* bench.c - timing loops over the pure parts of netman: scoring, config parsing, the firewall renderer, VPN profile import.
 * Nothing here touches the network, root or the host's files except reading tests/vpn_samples and src/netman.conf.example.
 * Built and run by ./bench from the repository root:
 *   cc -std=gnu11 -O1 -Isrc -Isrc/mods -Isrc/mods/vpn -o OUT tests/bench.c src/config.c <vpn module sources> && OUT
 * Prints markdown rows: name, calls per sample, then median / min / max time of ONE call over SAMPLES samples (after one
 * warm-up sample). The result of every call goes to a volatile sink so the compiler cannot drop the work. */
#define _GNU_SOURCE
#define NETMAN_SCORING_IMPLEMENTATION
#define NETMAN_NET_IMPLEMENTATION
#define NETMAN_FW_IMPLEMENTATION
#include "config.h"
#include "mods/firewall.h"
#include "mods/net.h"
#include "mods/scoring.h"
#include "mods/vpn/vpnimport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SAMPLES 11

static volatile long sink;

static double now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static int cmp(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;
	return x < y ? -1 : x > y;
}

static void report(const char *name, long calls, double *s)
{
	const char *unit = "ns";
	double div = 1e-9, m, lo, hi;
	qsort(s, SAMPLES, sizeof *s, cmp);
	m = s[SAMPLES / 2] / (double)calls;
	if (m > 5e-6) { unit = "us"; div = 1e-6; }
	lo = s[0] / (double)calls;
	hi = s[SAMPLES - 1] / (double)calls;
	printf("| %s | %ld | %.1f %s [%.1f..%.1f] |\n", name, calls, m / div, unit, lo / div, hi / div);
}

#define BENCH(name, calls, body)                                              \
	do {                                                                  \
		double s_[SAMPLES + 1];                                       \
		int r_;                                                       \
		for (r_ = 0; r_ < SAMPLES + 1; r_++) {                        \
			double t0_ = now();                                   \
			long i_;                                              \
			for (i_ = 0; i_ < (calls); i_++) { body; }            \
			s_[r_] = now() - t0_;                                 \
		}                                                             \
		report(name, calls, s_ + 1); /* sample 0 is the warm-up */    \
	} while (0)

static char *slurp(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	char *b;
	long n;
	if (!f) { fprintf(stderr, "bench.c: cannot read %s (run from the repository root)\n", path); exit(2); }
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	b = malloc((size_t)n + 1);
	*len = fread(b, 1, (size_t)n, f);
	b[*len] = 0;
	fclose(f);
	return b;
}

static nmfw_cfg rich(void)
{
	nmfw_cfg c;
	nmfw_rule r;
	nmfw_preset(&c, "workstation");
	nmfw_set_zone(&c, "lo0", "trusted");
	nmfw_set_zone(&c, "eth0", "home");
	nmfw_set_zone(&c, "wl0", "public");
	nmfw_set_zone(&c, "usb*", "untrusted");
	nmfw_parse_rule("allow in tcp port 22,80 from 10.0.0.0/8 on eth0 rate 5 # ssh", &r); nmfw_add_rule(&c, &r);
	nmfw_parse_rule("logdrop in v6 tcp port 23", &r); nmfw_add_rule(&c, &r);
	nmfw_parse_rule("reject out udp port 9999 to 203.0.113.0/24", &r); nmfw_add_rule(&c, &r);
	nmfw_parse_rule("allow fwd on wl0 via eth0 new est", &r); nmfw_add_rule(&c, &r);
	c.ra_guard = 1;
	snprintf(c.ra_router, sizeof c.ra_router, "fe80::1");
	snprintf(c.dhcp_server, sizeof c.dhcp_server, "192.168.1.1");
	snprintf(c.gw_ip, sizeof c.gw_ip, "192.168.1.1");
	snprintf(c.gw_mac, sizeof c.gw_mac, "aa:bb:cc:dd:ee:ff");
	return c;
}

int main(void)
{
	static const char *const samples[] = {
		"tests/vpn_samples/nm-wireguard.nmconnection", "tests/vpn_samples/nm-openvpn.nmconnection", "tests/vpn_samples/nm-strongswan.nmconnection",
		"tests/vpn_samples/swanctl.conf", "tests/vpn_samples/nm-l2tp.nmconnection", "tests/vpn_samples/nm-openconnect.nmconnection",
		"tests/vpn_samples/ipsec.conf", "tests/vpn_samples/client.ovpn", "tests/vpn_samples/wg-quick.conf",
	};
	netman_score_in in[64];
	netman_gwstat g;
	netman_config c;
	nmfw_cfg fw = rich();
	char e[400], norm[256], msg[300], *pbuf = malloc(1 << 16);
	size_t cl, i;
	char *conf = slurp("src/netman.conf.example", &cl);
	int k;

	puts("| case | calls per sample | time per call, median [min..max] |");
	puts("|---|---|---|");

	for (i = 0; i < 64; i++) { /* a spread of inputs, so the branches are all taken */
		netman_score_in_init(&in[i]);
		in[i].wired = (int)(i & 1);
		in[i].signal_dbm = (i & 2) ? -30 - (int)i : NETMAN_UNKNOWN;
		in[i].rtt_ms = (i & 4) ? (int)i * 7 - 2 : NETMAN_UNKNOWN;
		in[i].loss_pct = (i & 8) ? (int)(i % 101) : NETMAN_UNKNOWN;
		in[i].probe = (i & 16) ? (int)(i % 3) - 1 : NETMAN_UNKNOWN;
	}
	BENCH("netman_score (64 different inputs)", 640000, sink += netman_score(&in[i_ & 63]));
	BENCH("netman_score_should_leave", 1000000, sink += netman_score_should_leave((int)(i_ % 100), (int)((i_ * 7) % 100)));
	netman_gwstat_init(&g);
	BENCH("netman_gwstat_add + netman_gwstat_loss", 1000000, { netman_gwstat_add(&g, (i_ % 5) ? 20 + (int)(i_ % 9) : -1); sink += netman_gwstat_loss(&g); });

	BENCH("netman_config_find (dotted key)", 200000, sink += netman_config_find((i_ & 1) ? "wifi.backend" : "roaming.probe_url"));
	BENCH("netman_config_suggest (typo)", 20000, sink += netman_config_suggest("wifi.enabeld", msg, sizeof msg));
	BENCH("netman_config_defaults", 100000, { netman_config_defaults(&c); sink += c.v[0][0]; });
	netman_config_defaults(&c);
	BENCH("netman_config_check_value, every key with its default", 200, for (k = 0; k < NC_N; k++) sink += netman_config_check_value(k, netman_config_default(k), norm, sizeof norm, msg, sizeof msg));
	e[0] = 0;
	BENCH("netman_config_parse of src/netman.conf.example", 2000, { netman_config_defaults(&c); sink += netman_config_parse(&c, conf, cl, "bench", e, sizeof e); });
	if (e[0]) fprintf(stderr, "bench.c: example config did not parse: %s\n", e);

	BENCH("nmfw_plan (nft text, workstation + zones + 4 rules + guards)", 20000, sink += nmfw_plan(&fw, pbuf, 1 << 16));
	BENCH("nmfw_plan_ipt v4", 20000, sink += nmfw_plan_ipt(&fw, 0, pbuf, 1 << 16));
	BENCH("nmfw_parse_rule", 100000, { nmfw_rule r; sink += nmfw_parse_rule("allow in tcp port 22,80 from 10.0.0.0/8 on eth0 rate 5 # ssh", &r); });

	for (i = 0; i < sizeof samples / sizeof *samples; i++) {
		size_t l;
		char *x = slurp(samples[i], &l), er[300], name[160];
		netman_vpnimp o;
		snprintf(name, sizeof name, "netman_vpnimp_convert %s (%zu bytes)", strrchr(samples[i], '/') + 1, l);
		BENCH(name, 5000, { if (netman_vpnimp_convert(x, l, &o, er, sizeof er) == 0) { sink += (long)o.len; netman_vpnimp_free(&o); } });
		free(x);
	}
	printf("\nnmfw_plan output %d bytes, nmfw_plan_ipt v4 %d bytes, example config %zu bytes, %d config keys\n", nmfw_plan(&fw, pbuf, 1 << 16), nmfw_plan_ipt(&fw, 0, pbuf, 1 << 16), cl, (int)NC_N);
	return (int)(sink == 42 && 0);
}
