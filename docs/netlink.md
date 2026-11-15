# netlink: the link modules (`bridge`, `vlan`, `route`, `link`, `dot1x`, `tether`, `bond`, plus `licence`, `key`, `wol`)

Files: `src/mods/netlink.c` + `netlink.h` (shared netlink helpers, the `.ent` profile parser/formatter/store and the kind dispatch), one file per module:
`nl_bond.c` (bonding/team), `nl_bridge.c` (bridge + STP + vlan filtering), `nl_vlan.c` (vlan/QinQ, macvlan, ipvlan, veth, dummy), `nl_route.c` (routes, rules and
tables, ECMP failover), `nl_link.c` (link settings, IPv6 / prefix delegation), `nl_dot1x.c` (wired 802.1X); `netlink_priv.h` (private helpers, not an API),
`wol.c` (Wake-on-LAN), `tether.c` (USB / Bluetooth tethering detection, share-out, client mode, BT PAN), `licence.c` + `licence.h` (licences,
hook renewal, WireGuard key rotation). Test: `tests/netlink_test.c` (run by `tests/run`). There is no "enterprise" switch: every feature is an ordinary module with its own `enabled` key (below), and the TUI shows their live state in
the Links tab. The old `ent` command group and the `[enterprise]` config section still work (see Compatibility).

This file replaces the old `enterprise-wiring.md`, which was a patch description for wiring the module in; the wiring is done and lives in
`src/cli.h` (command table), `src/config.h` / `src/config.c` (the keys), `src/help.c` and `src/netman.c`. The source of truth for commands is
`netman help bridge|vlan|route|link|dot1x|tether|ent|licence|key|wol` and `src/netman.conf.example`.

## Build

Nothing special: the modules are in `src/sources` and `tools/cc` / `./run` link them. Bluetooth PAN additionally needs `-DNETMAN_NL_DBUS` and
dbus.h's implementation in the same translation unit as tether.c, which a separate .c cannot get from netman.c's static dbus code; until bluez PAN
is wanted the flag stays off and `btpan` returns -ENOSYS with a clear message.

## Config (all in `src/netman.conf.example`)

One section per module, each with `enabled` (off by default for the ones that change links and routes; a module that is off refuses its commands, like every other module; `netman ent list` still lists all profiles):
`[bridge]`, `[vlan]` (vlan, QinQ, macvlan, ipvlan, veth, dummy), `[route]` (routes, rules, ECMP; `probe_ms` = ECMP probe timeout and tick),
`[link]` (ethtool, MTU, IPv6, Wake-on-LAN), `[dot1x]`, `[tether]`, `[bonding]`. `[licence]` switches the `licence` and `key` groups and holds
`dir`, `warn_days`, `renew_hook`, `key_apply_hook`.

### Compatibility

The old `[enterprise]` section (and `NETMAN_ENTERPRISE_*` variables) still loads: `enabled` turns bridge, vlan, route, link and dot1x on or off
together, `probe_ms` is `route.probe_ms`, `licence_dir` / `licence_warn_days` / `renew_hook` / `key_apply_hook` are the `[licence]` keys. `netman ent ...`
stays as the all-in-one spelling of the module commands; each profile is still gated by its own module.

## Commands

    netman bridge|vlan|route|link|dot1x|tether  list | show NAME | save NAME [KIND] [KEY=VALUE...] | add NAME | del NAME
    netman route ecmp NAME      netman tether detect
    netman ent list|show NAME|save NAME KIND [KEY=VALUE...]|add NAME|del NAME|apply|ecmp NAME|tether     (old all-in-one spelling; apply = every profile of an enabled module)
    netman wol IFACE MAC
    netman licence status|renew NAME            (status exits 1 when anything expires soon: usable in cron)
    netman key rotate NAME|show NAME

Profiles are `NAME.ent` files (`key = value`, same syntax as net profiles) in the netman config directory. `team` is bonding: the kernel team driver
is deprecated, so `kind=team` maps `runner=` (activebackup, lacp, loadbalance, broadcast, roundrobin) onto the bonding driver. Tethering share-out
uses its own nft table `inet netman_tether` (firewall.h replaces `inet netman`, so the two never clobber each other); an accept there cannot override
a drop in another table, so a strict firewall must allow the downstream interface itself.

## What is and is not verified

Tested in `unshare -Urn` (177 checks, `tests/netlink_test.c`): spec parse/format, dummy, bonding (active-backup, balance-xor, broadcast, 802.3ad
with lacp_rate and hash policy, primary), team mapping, bridge (STP, forward delay, vlan filtering, per-port vlans),
vlan, QinQ, macvlan, ipvlan, veth, routes (tables incl. >255, blackhole, v6), rules, ECMP (scripted hysteresis plus real
ICMP against a peer netns), link MTU/offloads, IPv6 sysctls and /64 carving, Wake-on-LAN packet and a real broadcast
received in a peer netns, tether detection against a fake sysfs, nft ruleset loaded into the kernel and listed back,
dnsmasq config syntax-checked by `dnsmasq --test`, 802.1X config text, licences, hook renewal, key rotation (RFC 7748
vector).

Skipped or unverifiable here: ethtool speed/duplex and Wake-on-LAN setting (dummy/lo drivers refuse); the dnsmasq and
wpa_supplicant daemons (cannot drop privileges / own /run in a single-uid user namespace); a real USB RNDIS/CDC phone;
Bluetooth PAN (needs bluez and the D-Bus build flag); 802.1X against a real authenticator.
