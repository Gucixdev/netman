# netman

## edit 
Glib chcemy i Gobject jezeli wprowadzaja naprawde duza wartosc XD 
pythona nie chcemy napewno 
ale to samo dbus api by bylo dropin i zgodne z standardami 
ma pokrywac cala funkcjonalnosc networkmanager ale tak jak nie snilo sie robic tego w pythonie 
a tui trzeba odswierzac recznie za pomoca r poprostu XD 


A small replacement for NetworkManager + bluez tooling, in plain C: no Python, no GLib, no libdbus. Backends are iwd or wpa_supplicant
for Wi-Fi and bluez for Bluetooth, plus own netlink/DHCP/DNS, WireGuard/OpenVPN, nftables and interface metrics. Short alias in prose: `netmgr`.

## Build and run

    ./build                     compile what changed (tools/cc, no make; BUILD_FORCE=1 ./build: everything, ~4 s)
    ./run                       ./build, then open the TUI
    ./install [-rebuild]        ./build (-rebuild: from scratch) and install for the user: ~/.local/bin/netman and the default profiles (PREFIX=/usr/local with sudo for the system)
    tests/run                   build and run every test (about 5 minutes)

## Usage

    bin/netman                  status of links, wifi, bluetooth and vpn
    bin/netman help [TOPIC]     every command grouped; `help wifi`, `help tui`, `help config`, `help --man`
    bin/netman -tui             the TUI (`--tui` and `-t` also work)
    bin/netman vpn import FILE  import a wg-quick, .ovpn, NM keyfile or swanctl profile

Config: `/etc/netman/netman.conf`, then `~/.config/netman/netman.conf`; `netman config show|check|set KEY VALUE`. Commands that need root
re-run themselves through sudo (`privileges.sudo = auto|always|never`).

## Status and limits

No resident daemon is needed; `netman daemon` is optional (autoconnect, NetworkManager D-Bus API). The optional mods (ssh, mesh, bonding,
tunnel) are off by default. Not tested: real tor, live strongSwan / L2TP / OpenConnect, real iwd / wpa_supplicant / bluez hardware, a real
sudo prompt. SSTP is recognised but not supported; PPTP is refused on purpose. Full list in [docs/tests.md](docs/tests.md).

## More

- [docs/howto.md](docs/howto.md): source layout, configuration, privileges, TUI, settings, VPN types, import, Tor, mods
- [docs/tests.md](docs/tests.md): the test suites, how to run one, what is not tested
- [docs/netlink.md](docs/netlink.md): the link modules (bridge, vlan, route, link, dot1x, tether)
- [docs/ssh-mesh-bond-tunnel.md](docs/ssh-mesh-bond-tunnel.md): the optional ssh, mesh, bonding and tunnel mods
- [docs/bench.md](docs/bench.md): `./bench` results for what runs without root or network (scoring, config, firewall renderer, VPN import, build time)
