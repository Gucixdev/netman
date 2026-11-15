# netman

Network and Bluetooth manager for Linux in plain C: one binary (about 0.9 MB, links only libc), a command line and a terminal UI.
No Python, no GLib, no libdbus. It talks to iwd or wpa_supplicant for Wi-Fi and to bluez for Bluetooth, and does links, DHCP, DNS,
nftables, WireGuard / OpenVPN and routing metrics itself. `netman daemon` can also serve the NetworkManager D-Bus API, so
NetworkManager clients can talk to it. Licence: MIT.

## Build and install

You need a C compiler (cc, gcc or clang) and Linux. No make, no autotools.

    ./build                  compile what changed into bin/netman (clean build 4 s on 12 cores, unchanged 0.4 s)
    ./run                    ./build, then open the TUI
    ./install [-rebuild]     install for the current user: ~/.local/bin/netman, the man page and the example profiles under
                             ~/.local/share. PREFIX=/usr/local (with sudo) installs system-wide, DESTDIR is honoured.

## Use

    netman                          interfaces, Wi-Fi, Bluetooth and VPN at a glance
    netman wifi list | connect SSID [PASSPHRASE] | disconnect | known
    netman bt list | scan | pair NAME_OR_MAC | connect NAME_OR_MAC
    netman net list | show IFACE | dhcp IFACE | set IFACE ADDR/LEN [GATEWAY]
    netman vpn list | import FILE | up NAME | down NAME     (wg-quick, .ovpn, NM keyfile, swanctl)
    netman -tui                     the terminal UI; `?` shows the keys
    netman help [GROUP|COMMAND]     every command; `netman wifi` alone lists the wifi commands
    netman config show | set KEY VALUE | check      netman --version

Commands that need root re-run themselves through sudo and say which command asked (`privileges.sudo = auto|always|never`).
Modules that create links or change routes (bridge, vlan, route, tor, ssh, mesh, bonding, tunnel and more) are off by default;
`netman config toggle ssh.enabled` turns one on. Configuration is `/etc/netman/netman.conf` then `~/.config/netman/netman.conf`
(`src/netman.conf.example` documents every key). Note that `wifi connect SSID PASSPHRASE` puts the passphrase on the command
line; the TUI asks for it in a masked prompt instead.

## Trying it without touching your network

Read-only commands (`netman`, `net list`, `config show`, `help`) are safe anywhere. For anything else use a user and network
namespace, which is how the test suite works:

    unshare -Urnm sh -c 'mount -t sysfs sysfs /sys; bin/netman net list'

## Tested

`tests/run` builds and runs 25 suites (unit tests under `unshare -Urnm`, command-line goldens, the TUI driven in tmux at 80x24 and
40x12 against fake iwd / wpa_supplicant / bluez, a private D-Bus daemon for the NetworkManager API, real WireGuard in a namespace).
It takes about 5 minutes; the tmux suites wait on screen text, so a failed one is run once more before it counts. It needs cc,
unshare, tmux and dbus-daemon (missing tools skip their suites). `tests/qemu/run` boots a throw-away VM and, on the machine it was
developed on, passed 32 checks (3 skipped), among them a real wpa_supplicant joining a WPA2 access point and the DHCP client.
`UNIT_CFLAGS="-fsanitize=address,undefined" tests/run` runs the unit tests under ASan and UBSan. Details: [docs/tests.md](docs/tests.md).

## Not verified

- Real hardware: no physical Wi-Fi adapter, Bluetooth adapter or Ethernet link was driven by the tests.
- iwd and bluez only through fakes; real wpa_supplicant only against `mac80211_hwsim` in the VM.
- Live strongSwan, L2TP and OpenConnect connections, and real Tor (the generated torrc and firewall rules are checked, Tor itself is not run).
- A real sudo password prompt, and `vpn up` / `down` as root from the TUI.
- `netman daemon` against a real NetworkManager client (libnm, nmcli, nm-applet); only a raw D-Bus client is tested.
- Only one machine (x86-64, Arch-based, kernel 7.x) and one C compiler setup; other distributions and libcs are untested.
- SSTP is recognised but not implemented; PPTP is refused on purpose (broken encryption).

## Documentation

- [docs/howto.md](docs/howto.md): source layout, configuration, privileges, TUI, settings, VPN types, import, Tor, optional mods
- [docs/tests.md](docs/tests.md): the suites and what they do not cover
- [docs/netlink.md](docs/netlink.md): bridge, vlan, route, link, dot1x and tether modules
- [docs/ssh-mesh-bond-tunnel.md](docs/ssh-mesh-bond-tunnel.md): the optional ssh, mesh, bonding and tunnel modules
- [docs/bench.md](docs/bench.md): timings of what runs without root or network
- [lean4/](lean4/README.md): Lean 4 models of the DHCP timers, scoring, hysteresis and kill-switch logic (the C is not proven)
