# netman benchmarks

Appended by `./bench`. Findings first, then the log.

## Findings

Nothing here needs root or a network, and nothing outside `src/` code is being slow: the pure parts of netman are all in the
nanosecond to tens-of-microseconds range, so there is no performance bug to report. What the numbers say:

1. The scoring and roaming decisions cost 3 to 8 ns per call (`netman_score` 8 ns, `netman_score_should_leave` 3 ns, one
   `gwstat` update 6 ns). They can run on every probe without a thought.
2. Config handling is cheap: parsing the whole documented example file (10 KB, 79 keys) takes 13 us, validating every key 9 us.
   The one slow-looking call is `netman_config_suggest` (the "did you mean" lookup) at 54 us, which only runs when a key is
   misspelled. `netman_config_find` is a linear scan at 450 ns for 79 keys, which would only matter with thousands of lookups.
3. The firewall renderer produces a 2.5 KB nft ruleset (workstation preset, zones, 4 rules, guards) in 2.6 us and the 1.8 KB
   iptables-restore text in 2.4 us. Importing a foreign VPN profile takes 40 ns (wg-quick, copied as is) to 6.5 us (swanctl).
4. `netman help`, `config show` and `config check` take 1.2 ms against a 0.9 ms fork-and-exec floor, so the process itself adds
   about 0.3 ms. `netman status` in an empty network namespace takes 4 ms, of which 2.2 ms is `unshare` itself. How long
   it takes on a machine with a real Wi-Fi and Bluetooth stack is NOT measured (it talks to iwd, wpa_supplicant, bluez).
5. The unit-test binaries are not benchmarks of the product: `config_test` takes 0.4 s because it feeds 22000 random inputs to
   the parser (each error path runs the 54 us suggestion lookup), `fw_test` 0.9 s and `wifi_bt_test` 1.8 s mostly wait for fake
   services and rollback timers (the min is almost equal to the median in `wifi_bt_test`, which says fixed sleeps; not
   verified line by line). The whole `tests/run` is about 5 minutes, dominated by the tmux tests, which are not timed here.
6. A clean build with `tools/cc` takes 4.5 s, and 0.11 s when nothing changed, matching the README claims (about 4 s, 0.1 s).

How sure: these rows were taken at a load average of about 9 on 12 threads. An earlier trial at load 20 made the ns-scale rows
2 to 3 times slower and the process rows 2 to 4 times slower, so on this shared machine treat absolute values as upper bounds;
the ratios between rows are stable. Not measured, because it needs root or a network: connecting, DHCP and DNS, the VPN
tunnels, real firewall application (`nft` is not run, only the text is rendered), D-Bus round trips to the NetworkManager
API (`tests/nmapi_test` runs a private bus but is a correctness test, not timed).

## Results log

## 2026-11-15, commit a009c96 (src unchanged; `bench` and `tests/bench.c` are the files added right after it)

machine: Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz, 12 threads, Linux 7.3.3-1-cachyos; cc (GCC) 16.2.1 20260810; shared with the owner's editors
load average at start: 8.99 14.48 11.39; timed rows: 1 warm-up run, then 9 runs
command: `./bench`; tests/bench.c built with `cc -std=gnu11 -O1 -Isrc -Isrc/mods -Isrc/mods/vpn` (the flags of tests/run), run in `unshare -Urn`

### Pure functions (tests/bench.c), time of one call; 11 samples per row after a warm-up sample

| case | calls per sample | time per call, median [min..max] |
|---|---|---|
| netman_score (64 different inputs) | 640000 | 8.1 ns [8.1..8.2] |
| netman_score_should_leave | 1000000 | 3.1 ns [2.4..4.4] |
| netman_gwstat_add + netman_gwstat_loss | 1000000 | 5.8 ns [5.5..6.3] |
| netman_config_find (dotted key) | 200000 | 447.6 ns [445.5..458.5] |
| netman_config_suggest (typo) | 20000 | 54.5 us [53.4..59.0] |
| netman_config_defaults | 100000 | 2838.9 ns [2802.1..2947.5] |
| netman_config_check_value, every key with its default | 200 | 8.8 us [8.6..8.9] |
| netman_config_parse of src/netman.conf.example | 2000 | 13.3 us [13.1..15.0] |
| nmfw_plan (nft text, workstation + zones + 4 rules + guards) | 20000 | 2632.5 ns [2563.0..2689.5] |
| nmfw_plan_ipt v4 | 20000 | 2414.7 ns [2375.0..2523.1] |
| nmfw_parse_rule | 100000 | 593.1 ns [588.1..612.4] |
| netman_vpnimp_convert nm-wireguard.nmconnection (348 bytes) | 5000 | 3956.0 ns [3763.2..3993.4] |
| netman_vpnimp_convert nm-openvpn.nmconnection (225 bytes) | 5000 | 3039.9 ns [3006.9..3623.4] |
| netman_vpnimp_convert nm-strongswan.nmconnection (149 bytes) | 5000 | 2224.6 ns [2204.3..2267.5] |
| netman_vpnimp_convert swanctl.conf (415 bytes) | 5000 | 6.5 us [6.3..9.4] |
| netman_vpnimp_convert nm-l2tp.nmconnection (177 bytes) | 5000 | 2513.3 ns [2491.9..2711.5] |
| netman_vpnimp_convert nm-openconnect.nmconnection (147 bytes) | 5000 | 1948.0 ns [1938.7..2401.1] |
| netman_vpnimp_convert ipsec.conf (235 bytes) | 5000 | 2685.9 ns [2479.6..2932.1] |
| netman_vpnimp_convert client.ovpn (83 bytes) | 5000 | 293.6 ns [272.5..406.5] |
| netman_vpnimp_convert wg-quick.conf (210 bytes) | 5000 | 41.2 ns [37.8..90.3] |

nmfw_plan output 2534 bytes, nmfw_plan_ipt v4 1761 bytes, example config 10446 bytes, 79 config keys

### Unit-test binaries, wall time of one run in `unshare -Urnm` (build excluded), ms

| test | checks | median | min | max |
|---|---|---|---|---|
| config_test | 51 checks | 406.49 | 401.98 | 412.92 |
| settings_test | 664 checks | 5.36 | 5.17 | 10.79 |
| priv_test | 15 checks | 6.11 | 5.59 | 9.77 |
| fw_test | 176 checks | 874.35 | 719.55 | 960.79 |
| wifi_bt_test | 75 checks | 1820.48 | 1817.59 | 2320.78 |
| net_score_test | 58 checks | 5.59 | 4.88 | 8.95 |

### The binary (bin/netman as built by ./run, 932272 bytes), one process per run, ms

| command | median | min | max |
|---|---|---|---|
| `true` (floor: fork and exec) | 0.88 | 0.84 | 0.97 |
| `unshare -Urn true` (floor of the rows marked ns) | 2.16 | 2.11 | 11.96 |
| `netman help` | 1.25 | 1.19 | 1.47 |
| `netman help wifi` | 1.20 | 1.15 | 1.28 |
| `netman config show` | 1.18 | 0.97 | 1.31 |
| `netman config check` | 1.21 | 1.01 | 1.38 |
| `netman status` (ns: only an empty loopback to list) | 3.98 | 3.82 | 4.87 |

### Build with tools/cc (all cores, -O1, in a copy of src and tools), wall seconds

clean build, 3 runs: 4.52 s [4.52..4.59]; nothing changed, 9 runs: 0.11 s [0.10..0.11]

load average at end: 8.01 12.73 11.02
