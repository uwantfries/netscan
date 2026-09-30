# netscan

A portable command-line tool that finds the devices on your network and checks which common ports they have open. It's written in C# (.NET 10) and ships as a single executable: nothing to install and no .NET runtime needed.

```
> netscan
Local network: WiFi, this machine is 192.168.1.231
Scanning 192.168.1.0/24 (254 addresses, 255 at a time, 1000 ms timeout)...
Pass 1 (quick) found 19 device(s) in 1.2s.
Pass 2 (deep) found 3 more in 12.5s, 22 in total.

Address          Name                  MAC               Found by                         Ping
----------------------------------------------------------------------------------------------
192.168.1.1                            aa:bb:cc:00:00:01 ping,tcp,arp                     2 ms
    22/tcp     ssh
    53/tcp     dns
    80/tcp     http
192.168.1.169    octopi.local          aa:bb:cc:00:00:02 ping,tcp,arp,mdns,ssdp           7 ms
    22/tcp     ssh
    80/tcp     http
192.168.1.194    dp-1234ABCD.local     aa:bb:cc:00:00:03 arp,arp-req,mdns                       (pass 2)
    no open ports found
...
```

## Usage

```
netscan [target] [options]
```

With no target, netscan scans the subnet of your active network adapter (at most a /24).

| Target | Meaning |
|---|---|
| `192.168.1.0/24` | CIDR block (up to a /16) |
| `192.168.1.10-50` | Range within the last octet |
| `192.168.1.10-192.168.1.50` | Full range |
| `192.168.1.20` | Single address |

| Option | Description |
|---|---|
| `-t, --threads <n>` | Checks run at the same time, 1–255 (default 255) |
| `-w, --timeout <ms>` | Timeout per ping or connection attempt (default 1000) |
| `-p, --ports <list>` | Ports to check, e.g. `22,80,443,8000-8100` (default: about 30 common ports) |
| `--no-ports` | Only find devices; skip the port check |
| `--quick` | Skip pass 2: faster, but finds fewer devices |
| `--watch <time>` | Keep looking for new devices for this long, e.g. `90s`, `5m`, `1h` |
| `--no-dns` | Don't look up host names |
| `-h, --help` | Show help |

Examples:

```
netscan                              # scan your own network
netscan 192.168.1.0/24 -p 22,80,443  # scan a subnet for SSH and web servers
netscan --no-ports --watch 5m        # list devices, and keep watching for 5 minutes
```

## How it finds devices

Many devices ignore ping, so netscan counts a device as found if any of these methods gets an answer. The **Found by** column shows which ones did.

**Pass 1 (quick, about 1 second):** one ping and a few TCP connection attempts per address. A connection that is *refused* still proves something is there. Afterwards netscan reads the operating system's ARP table, which lists the hardware (MAC) address of every device that answered at the network level. This catches devices that ignore both ping and TCP.
