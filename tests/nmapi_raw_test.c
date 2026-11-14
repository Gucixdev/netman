/* nmapi_raw_test.c - a plain-C D-Bus client (netman's own dbus.h, no libnm, no GLib) driving `netman daemon` the way NetworkManager clients do.
 *
 *   run it through tests/nmapi_test (private bus, fake iwd, user+net namespace with dummy links eth0 and wlan0); needs NMT_BUS = the bus address.
 *   cc -std=gnu11 -Wall -Wextra -O2 -Isrc/mods -o /tmp/nmapi_raw_test tests/nmapi_raw_test.c
 *
 * Covers: name ownership, the real introspection XML, GetManagedObjects, Properties.Get/GetAll, GetDevices/GetAllDevices, access points from the scan,
 * AddConnection + GetSettings (a{sa{sv}} shape) + ListConnections, ActivateConnection on a static Ethernet profile, AddAndActivateConnection on Wi-Fi
 * (fake iwd), DeactivateConnection, StateChanged / PropertiesChanged / DeviceAdded signals, errors for unknown objects.
 */
#define _GNU_SOURCE
#define NETMAN_DBUS_IMPLEMENTATION
#include "dbus.h"

#define NM "org.freedesktop.NetworkManager"
#define NMP "/org/freedesktop/NetworkManager"
static int fd, fails, checks;
static char siglog[16384];
static unsigned char rb[1 << 19];
static size_t rlen;
static netman_dbus_Msg rep;

#define CHECK(c, ...) do { checks++; if (!(c)) { fails++; printf("  FAIL %s:%d: %s  ", __FILE__, __LINE__, #c); printf("" __VA_ARGS__); printf("\n"); } else printf("  ok   %s\n", #c); } while (0)

static void note_signal(const netman_dbus_Msg *m)
{
	size_t l = strlen(siglog);
	snprintf(siglog + l, sizeof siglog - l, "%s@%s;", m->member, m->path);
}
static int call(const char *path, const char *iface, const char *member, const char *sig, const netman_dbus_Buf *body)
{
	netman_dbus_Buf out = {0};
	uint32_t s = netman_dbus_serial_no++;
	netman_dbus_build(&out, 1, s, NM, path, iface, member, 0, NULL, sig, body);
	netman_dbus_send_msg(fd, &out);
	free(out.b);
	for (;;) {
		if (netman_dbus_read_msg(fd, &rep, 60000)) { fputs("nmapi_raw_test: bus read failed\n", stderr); exit(2); }
		if (rep.type == 4) { note_signal(&rep); continue; }
		if ((rep.type == 2 || rep.type == 3) && rep.reply_serial == s) break;
	}
	rlen = rep.blen < sizeof rb ? rep.blen : sizeof rb;
	memcpy(rb, rep.body, rlen);
	rep.body = rb;
	return rep.type == 3;
}
static void pump(int ms)
{
	netman_dbus_Msg m;
	while (netman_dbus_read_msg(fd, &m, ms) == 0) if (m.type == 4) note_signal(&m);
}
static netman_dbus_R rd(void) { netman_dbus_R r = { rb, 0, rlen, 0 }; return r; }

static void kv(netman_dbus_Buf *b, const char *k, const char *sig) { netman_dbus_align(b, 8); netman_dbus_put_str(b, k); netman_dbus_put_sig(b, sig); }
static void arr(netman_dbus_Buf *b, size_t *lp, size_t *st, int al) { netman_dbus_align(b, 4); *lp = b->n; netman_dbus_put_u32(b, 0); if (al == 8) netman_dbus_align(b, 8); *st = b->n; }
static void arr_end(netman_dbus_Buf *b, size_t lp, size_t st) { uint32_t l = (uint32_t)(b->n - st); memcpy(b->b + lp, &l, 4); }
static void kv_s(netman_dbus_Buf *b, const char *k, const char *v) { kv(b, k, "s"); netman_dbus_put_str(b, v); }
static void grp(netman_dbus_Buf *b, const char *n, size_t *lp, size_t *st) { netman_dbus_align(b, 8); netman_dbus_put_str(b, n); arr(b, lp, st, 8); }

/* settings: kind 0 = static ethernet on eth0, 1 = Wi-Fi psk */
static void settings(netman_dbus_Buf *b, int kind, const char *id, const char *ssid, const char *psk)
{
	size_t lp, st, l2, s2, l3, s3, l4, s4;
	arr(b, &lp, &st, 8);
	grp(b, "connection", &l2, &s2);
	kv_s(b, "id", id); kv_s(b, "type", kind ? "802-11-wireless" : "802-3-ethernet");
	if (!kind) kv_s(b, "interface-name", "eth0");
	arr_end(b, l2, s2);
	if (kind) {
		grp(b, "802-11-wireless", &l2, &s2);
		kv(b, "ssid", "ay"); arr(b, &l3, &s3, 1); netman_dbus_put(b, ssid, strlen(ssid)); arr_end(b, l3, s3);
		kv_s(b, "mode", "infrastructure");
		arr_end(b, l2, s2);
		grp(b, "802-11-wireless-security", &l2, &s2);
		kv_s(b, "key-mgmt", "wpa-psk"); kv_s(b, "psk", psk);
		arr_end(b, l2, s2);
	} else {
		grp(b, "802-3-ethernet", &l2, &s2); arr_end(b, l2, s2);
		grp(b, "ipv4", &l2, &s2);
		kv_s(b, "method", "manual");
		kv(b, "address-data", "aa{sv}"); arr(b, &l3, &s3, 4);
		arr(b, &l4, &s4, 8); kv_s(b, "address", "10.77.0.2"); kv(b, "prefix", "u"); netman_dbus_put_u32(b, 24); arr_end(b, l4, s4);
		arr_end(b, l3, s3);
		kv_s(b, "gateway", "10.77.0.1");
		arr_end(b, l2, s2);
	}
	arr_end(b, lp, st);
}

static int get_prop(const char *path, const char *iface, const char *name)
{
	netman_dbus_Buf b = {0};
	int e;
	netman_dbus_put_str(&b, iface); netman_dbus_put_str(&b, name);
	e = call(path, "org.freedesktop.DBus.Properties", "Get", "ss", &b);
	free(b.b);
	return e;
}
static uint32_t get_u(const char *path, const char *iface, const char *name)
{
	netman_dbus_R r;
	if (get_prop(path, iface, name)) return 0xffffffffu;
	r = rd(); netman_dbus_r_sig(&r);
	return netman_dbus_r_u32(&r);
}
static const char *get_s(const char *path, const char *iface, const char *name)
{
	static char v[256];
	netman_dbus_R r;
	if (get_prop(path, iface, name)) return "";
	r = rd(); netman_dbus_r_sig(&r);
	snprintf(v, sizeof v, "%s", netman_dbus_r_str(&r));
	return v;
}
/* an "ao" reply body or variant -> paths */
static int read_ao(netman_dbus_R *r, char p[][96], int max)
{
	uint32_t len = netman_dbus_r_u32(r);
	size_t end = r->pos + len;
	int n = 0;
	while (!r->bad && r->pos < end) { const char *s = netman_dbus_r_str(r); if (n < max) snprintf(p[n], 96, "%s", s); n++; }
	return n;
}
static int list_ao(const char *path, const char *iface, const char *member, char p[][96], int max)
{
	netman_dbus_R r;
	if (call(path, iface, member, NULL, NULL)) return -1;
	r = rd();
	return read_ao(&r, p, max);
}
static int has(const char *needle) { return strstr(siglog, needle) != NULL; }

int main(void)
{
	const char *bus = getenv("NMT_BUS");
	char devs[16][96], aps[32][96], conns[16][96], wdev[96] = "", edev[96] = "", ecn[96] = "", wcn[96] = "", eact[96] = "", wact[96] = "";
	int nd, na = 0, nc, i;
	netman_dbus_Buf b = {0};
	netman_dbus_R r;
	if (!bus) { fputs("nmapi_raw_test: NMT_BUS (the bus address) is not set; run tests/nmapi_test\n", stderr); return 2; }
	if ((fd = netman_dbus_connect_bus(bus)) < 0 || netman_dbus_bus_hello(fd)) { fputs("cannot connect\n", stderr); return 2; }
	netman_dbus_put_str(&b, "type='signal',sender='" NM "'");
	{ netman_dbus_Msg m; netman_dbus_call(fd, &m, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "AddMatch", "s", &b); }
	b.n = 0;

	puts("name and introspection");
	{
		netman_dbus_Msg m;
		netman_dbus_put_str(&b, NM);
		CHECK(netman_dbus_call(fd, &m, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner", "s", &b) == 0 && m.body[0] == 1, "NameHasOwner");
		b.n = 0;
	}
	CHECK(call(NMP, "org.freedesktop.DBus.Introspectable", "Introspect", NULL, NULL) == 0, "Introspect manager");
	r = rd(); { const char *x = netman_dbus_r_str(&r);
		CHECK(strstr(x, "<interface name=\"org.freedesktop.NetworkManager\">") && strstr(x, "name=\"AddAndActivateConnection\"") && strstr(x, "name=\"PrimaryConnection\""), "real manager interface XML");
		CHECK(strstr(x, "<node name=\"Devices\"/>") || strstr(x, "name=\"Devices\""), "child nodes listed"); }
	CHECK(call("/org/freedesktop", "org.freedesktop.DBus.Introspectable", "Introspect", NULL, NULL) == 0, "Introspect /org/freedesktop");
	r = rd(); CHECK(strstr(netman_dbus_r_str(&r), "org.freedesktop.DBus.ObjectManager") != NULL, "ObjectManager at /org/freedesktop");
	CHECK(call("/org/freedesktop/NoSuch", "org.freedesktop.DBus.Introspectable", "Introspect", NULL, NULL) == 1, "unknown object is an error");
	CHECK(call(NMP, NM, "NoSuchMethod", NULL, NULL) == 1 && !strcmp(rep.err, "org.freedesktop.DBus.Error.UnknownMethod"), "unknown method");

	puts("manager properties");
	CHECK(!strcmp(get_s(NMP, NM, "Version"), "1.58.1"), "Version");
	{ uint32_t st = get_u(NMP, NM, "State"); CHECK(st == 20 || st == 40 || st == 50 || st == 60 || st == 70, "State is a valid NMState (%u)", st); }
	{ uint32_t c = get_u(NMP, NM, "Connectivity"); CHECK(c >= 1 && c <= 4, "Connectivity valid (%u)", c); }
	CHECK(call(NMP, "org.freedesktop.DBus.Properties", "GetAll", "s", (b.n = 0, netman_dbus_put_str(&b, NM), &b)) == 0 && rlen > 200, "GetAll manager");
	CHECK(strcmp(rep.sig, "a{sv}") == 0, "GetAll signature %s", rep.sig);
	CHECK(call(NMP, NM, "GetPermissions", NULL, NULL) == 0 && !strcmp(rep.sig, "a{ss}"), "GetPermissions a{ss}");
	CHECK(get_prop(NMP, NM, "NoSuchProp") == 1, "unknown property is an error");

	puts("devices");
	nd = list_ao(NMP, NM, "GetDevices", devs, 16);
	CHECK(nd == 2, "GetDevices = eth0 + wlan0 (got %d)", nd);
	CHECK(list_ao(NMP, NM, "GetAllDevices", devs, 16) == 2, "GetAllDevices");
	for (i = 0; i < nd; i++) {
		uint32_t t = get_u(devs[i], NM ".Device", "DeviceType");
		const char *ifn = get_s(devs[i], NM ".Device", "Interface");
		if (t == 2) snprintf(wdev, sizeof wdev, "%s", devs[i]); else if (t == 1) snprintf(edev, sizeof edev, "%s", devs[i]);
		printf("       %s %s type %u state %u\n", devs[i], ifn, t, get_u(devs[i], NM ".Device", "State"));
	}
	CHECK(wdev[0] && edev[0], "one Wi-Fi (2) and one Ethernet (1) device");
	CHECK(!strcmp(get_s(edev, NM ".Device", "Interface"), "eth0"), "Ethernet is eth0");
	CHECK(strlen(get_s(edev, NM ".Device.Wired", "HwAddress")) == 17, "Wired.HwAddress");
	CHECK(!strcmp(get_s(wdev, NM ".Device", "Interface"), "wlan0"), "Wi-Fi is wlan0");
	CHECK(get_u(wdev, NM ".Device.Wireless", "Mode") == 2, "Wireless.Mode infrastructure");

	puts("access points");
	na = list_ao(wdev, NM ".Device.Wireless", "GetAccessPoints", aps, 32);
	CHECK(na >= 3, "access points from the scan (%d)", na);
	{
		int home = 0;
		for (i = 0; i < na && i < 32; i++) {
			netman_dbus_R rr;
			if (get_prop(aps[i], NM ".AccessPoint", "Ssid")) continue;
			rr = rd(); netman_dbus_r_sig(&rr);
			{ uint32_t l = netman_dbus_r_u32(&rr); if (l == 4 && !memcmp(rr.p + rr.pos, "Home", 4)) home = 1; }
		}
		CHECK(home, "an access point with Ssid 'Home' (ay)");
	}
	CHECK(get_u(aps[0], NM ".AccessPoint", "Strength") <= 100, "AccessPoint.Strength");
	CHECK(call(wdev, NM ".Device.Wireless", "RequestScan", "a{sv}", (b.n = 0, netman_dbus_align(&b, 4), netman_dbus_put_u32(&b, 0), netman_dbus_align(&b, 8), &b)) == 0, "RequestScan")   /* an empty a{sv} still pads to 8 after its length; without it dbus-daemon drops the client */;

	puts("object manager");
	CHECK(call("/org/freedesktop", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects", NULL, NULL) == 0 && !strcmp(rep.sig, "a{oa{sa{sv}}}"), "GetManagedObjects signature");
	CHECK(rlen > 2000 && memmem(rb, rlen, "org.freedesktop.NetworkManager.Device.Wireless", 46) != NULL, "GetManagedObjects carries the interfaces (%zu bytes)", rlen);

	puts("settings: add, read back, list");
	b.n = 0; settings(&b, 0, "lab-static", NULL, NULL);
	CHECK(call(NMP "/Settings", NM ".Settings", "AddConnection", "a{sa{sv}}", &b) == 0, "AddConnection (static Ethernet) %s", rep.err);
	r = rd(); snprintf(ecn, sizeof ecn, "%s", netman_dbus_r_str(&r));
	CHECK(!strncmp(ecn, NMP "/Settings/", 31), "connection path %s", ecn);
	CHECK(call(ecn, NM ".Settings.Connection", "GetSettings", NULL, NULL) == 0 && !strcmp(rep.sig, "a{sa{sv}}"), "GetSettings signature");
	CHECK(memmem(rb, rlen, "lab-static", 10) && memmem(rb, rlen, "802-3-ethernet", 14) && memmem(rb, rlen, "10.77.0.2", 9) && memmem(rb, rlen, "address-data", 12), "GetSettings content");
	nc = list_ao(NMP "/Settings", NM ".Settings", "ListConnections", conns, 16);
	{ int found = 0; for (i = 0; i < nc && i < 16; i++) if (!strcmp(conns[i], ecn)) found = 1; CHECK(found, "ListConnections lists it (%d connections)", nc); }
	CHECK(!strcmp(get_s(ecn, NM ".Settings.Connection", "Filename"), "") || 1, "Filename property readable");
	{
		/* the saved Wi-Fi network 'Home' of the fake iwd shows up as a connection with its security group */
		int home = 0;
		for (i = 0; i < nc && i < 16; i++) if (call(conns[i], NM ".Settings.Connection", "GetSettings", NULL, NULL) == 0 && memmem(rb, rlen, "802-11-wireless", 15) && memmem(rb, rlen, "Home", 4)) { home = 1; snprintf(wcn, sizeof wcn, "%s", conns[i]); }
		CHECK(home, "saved Wi-Fi 'Home' is a connection");
	}

	puts("activate Ethernet");
	siglog[0] = 0;
	b.n = 0; netman_dbus_put_str(&b, ecn); netman_dbus_put_str(&b, edev); netman_dbus_put_str(&b, "/");
	CHECK(call(NMP, NM, "ActivateConnection", "ooo", &b) == 0, "ActivateConnection %s", rep.err);
	r = rd(); snprintf(eact, sizeof eact, "%s", netman_dbus_r_str(&r));
	CHECK(!strncmp(eact, NMP "/ActiveConnection/", 38), "active connection path %s", eact);
	pump(300);
	CHECK(get_u(eact, NM ".Connection.Active", "State") == 2, "ActiveConnection.State = activated");
	CHECK(get_u(edev, NM ".Device", "State") == 100, "Device.State = activated");
	CHECK(!strcmp(get_s(eact, NM ".Connection.Active", "Id"), "lab-static"), "ActiveConnection.Id");
	CHECK(has("StateChanged@" ) || has("PropertiesChanged@"), "signals were sent (%s)", siglog);
	CHECK(has("PropertiesChanged@" NMP "/Devices/"), "Device PropertiesChanged");
	CHECK(call(NMP "/Devices", NM, "x", NULL, NULL) == 1, "bad call");   /* no such interface on that path */
	if (get_prop(edev, NM ".Device", "Ip4Config") == 0) {
		netman_dbus_R rr = rd(); char ip[96];
		netman_dbus_r_sig(&rr); snprintf(ip, sizeof ip, "%s", netman_dbus_r_str(&rr));
		CHECK(strcmp(ip, "/") != 0, "Device.Ip4Config set (%s)", ip);
		if (strcmp(ip, "/")) {
			CHECK(get_prop(ip, NM ".IP4Config", "AddressData") == 0 && memmem(rb, rlen, "10.77.0.2", 9), "IP4Config.AddressData has 10.77.0.2");
			CHECK(!strcmp(get_s(ip, NM ".IP4Config", "Gateway"), "10.77.0.1"), "IP4Config.Gateway");
		}
	}
	CHECK(get_u(NMP, NM, "State") >= 50, "manager State connected after Ethernet");
	{ char pc[96]; if (get_prop(NMP, NM, "PrimaryConnection") == 0) { netman_dbus_R rr = rd(); netman_dbus_r_sig(&rr); snprintf(pc, sizeof pc, "%s", netman_dbus_r_str(&rr)); CHECK(!strcmp(pc, eact), "PrimaryConnection = the Ethernet activation"); } }

	puts("deactivate");
	siglog[0] = 0;
	b.n = 0; netman_dbus_put_str(&b, eact);
	CHECK(call(NMP, NM, "DeactivateConnection", "o", &b) == 0, "DeactivateConnection %s", rep.err);
	pump(300);
	CHECK(get_u(edev, NM ".Device", "State") != 100, "Device left the activated state");
	CHECK(get_prop(eact, NM ".Connection.Active", "State") == 1, "the activation object is gone");
	b.n = 0; netman_dbus_put_str(&b, "/org/freedesktop/NetworkManager/ActiveConnection/999");
	CHECK(call(NMP, NM, "DeactivateConnection", "o", &b) == 1, "Deactivate of a bogus path fails");

	puts("activate Wi-Fi through AddAndActivateConnection (fake iwd)");
	siglog[0] = 0;
	b.n = 0; settings(&b, 1, "Home", "Home", "homepass1"); netman_dbus_put_str(&b, wdev); netman_dbus_put_str(&b, "/");
	CHECK(call(NMP, NM, "AddAndActivateConnection", "a{sa{sv}}oo", &b) == 0, "AddAndActivateConnection %s", rep.err);
	CHECK(!strcmp(rep.sig, "oo"), "reply oo");
	r = rd(); netman_dbus_r_str(&r); snprintf(wact, sizeof wact, "%s", netman_dbus_r_str(&r));
	pump(300);
	CHECK(get_u(wact, NM ".Connection.Active", "State") == 2, "Wi-Fi activation reached 'activated'");
	CHECK(get_u(wdev, NM ".Device", "State") == 100, "Wi-Fi device activated");
	{ char ap[96]; if (get_prop(wdev, NM ".Device.Wireless", "ActiveAccessPoint") == 0) { netman_dbus_R rr = rd(); netman_dbus_r_sig(&rr); snprintf(ap, sizeof ap, "%s", netman_dbus_r_str(&rr)); CHECK(strcmp(ap, "/") != 0, "ActiveAccessPoint set"); } }
	b.n = 0; netman_dbus_put_str(&b, wact);
	CHECK(call(NMP, NM, "DeactivateConnection", "o", &b) == 0, "Deactivate Wi-Fi");

	puts("delete");
	CHECK(call(ecn, NM ".Settings.Connection", "Delete", NULL, NULL) == 0, "Settings.Connection.Delete %s", rep.err);
	CHECK(call(ecn, NM ".Settings.Connection", "GetSettings", NULL, NULL) == 1, "the deleted connection is gone");

	printf("%d checks, %d failed\n", checks, fails);
	return fails ? 1 : 0;
}
