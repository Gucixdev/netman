# netman: tests

    tests/run                                    builds and runs ALL of the below (about 5 minutes, idle machine; tmux tests can miss a deadline under load)
    UNIT_CFLAGS="-g -fsanitize=address,undefined -fno-omit-frame-pointer" tests/run    the same with the unit tests built under ASan+UBSan (leaks fail a test)

The individual commands, for running one:

    cc -std=gnu11 -Wall -Wextra -O2 -Isrc -Isrc/mods -Isrc/mods/vpn -DNETMAN_NO_MAIN -o /tmp/nm_logic tests/logic_test.c src/config.c src/mods/netlink.c src/mods/nl_bond.c src/mods/nl_bridge.c src/mods/nl_vlan.c src/mods/nl_route.c src/mods/nl_link.c src/mods/nl_dot1x.c src/mods/wol.c src/mods/tether.c src/mods/licence.c src/mods/wireguard.c && /tmp/nm_logic   76 checks (parsers, width, render, modals)
    tests/pty                                    the real binary in tmux against fake iwd / wpa_supplicant / bluez (tests/fakes.c): 141 checks
    tests/cli_test                               help, man sync, config, module gating, exit codes (57)
    tests/priv_test.c (15), tests/config_test.c (45; src/config.c [src/netman.conf.example])
    tests/vpnmod_test.c (VPN module goldens, fake swanctl/openconnect, import samples in tests/vpn_samples, xl2tpd parses the config), tests/tor_test.c (torrc/nft goldens, fake control server, nft rules loaded in `unshare -Urn`: redirect, leak dropped, fail closed), tests/pty_tor (Tor tab + VPN types, 80x24 and 40x12), tests/pty_netlink (Enterprise tab, 80x24 and 40x12), tests/pty_vpn (real WireGuard in unshare -Urn, drives the VPN tab), tests/wifi_bt_test.c (75), net_test (+ `selftest` under unshare -Urn), vpn_test (+ live WireGuard peer edits under ns), fw_test, net_score_test (unshare -Urn)

    tests/settings_test.c (schema consistency: every config key has an entry; 616 checks), tests/settings_cli_test (settings goldens, JSON validity, atomic writes, pick through a fake menu), tests/pty_settings (the Settings tab in tmux under `unshare -Urn`: keys, mouse, 80x24 and 40x12)

    tests/nmapi_test (the D-Bus NetworkManager API served by `netman daemon`, 60 checks: a private dbus-daemon, a raw-wire client in tests/nmapi_raw_test.c, `unshare -Urnm`), tests/ssh_test.c, mesh_test.c, bonding_test.c, tunnel_test.c (fake ssh / ssh-keyscan / ip / batctl, real netlink in `unshare -Urn`), tests/pty_mods (the four tabs in the real TUI)

Not tested: real tor (not installed here: bootstrap, circuits, bridges, hidden services), a live strongSwan / L2TP / OpenConnect connection (binaries absent or no server: config and argv only), real iwd / wpa_supplicant / bluez and real hardware, real networks, a real sudo prompt, vpn up/down as root from the TUI, the DHCP lease-cache
key used by the details pane (a guess: the SSID), `netman daemon` against a real libnm / nmcli client (tests/nmapi_libnm_test.c is not written).
