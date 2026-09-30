# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`netscan`: a portable C# (.NET 10) command-line LAN scanner. It finds devices on a subnet, then checks common TCP ports on each device found. It ships as a single self-contained, trimmed executable.

## Commands

```sh
dotnet build
dotnet test
dotnet test --filter "FullyQualifiedName~IpRangeTests"                 # one class
dotnet test --filter "FullyQualifiedName~IpRangeTests.Contains_checks_bounds"   # one test

dotnet run --project src/NetScan                                # scan the local subnet
dotnet run --project src/NetScan -- 192.168.1.0/24 -t 64 -p 22,80,443 --no-dns
dotnet run --project src/NetScan -- --quick --no-ports            # pass 1 only, no port scan
dotnet run --project src/NetScan -- --watch 5m                    # keep looking for sleeping devices for 5 minutes

# Portable exe (~11 MB). Use other RIDs for other platforms: linux-x64, linux-arm64, osx-arm64
dotnet publish src/NetScan -c Release -r win-x64 -o publish/win-x64
```

The single-file, self-contained and trimming settings in [src/NetScan/NetScan.csproj](src/NetScan/NetScan.csproj) apply only when a RuntimeIdentifier is set, so plain `dotnet build`/`test` stay normal. Because the published build is **trimmed**, avoid reflection-based APIs (e.g. reflection JSON serialization) and check `dotnet publish` for trim warnings after adding dependencies.

## Architecture

[Program.cs](src/NetScan/Program.cs) runs the pipeline: parse options → resolve the target range (or auto-detect it) → discovery pass 1 → discovery pass 2 (unless `--quick`) → port scan and reverse DNS in parallel → print a table sorted by IP.

All discovery results go into a `HostSet` (thread-safe, keyed by IP, ignores addresses outside the range). Each `DiscoveredHost` stores a `[Flags] Method` recording every way it was found, which becomes the Found-by column.

- **Pass 1** (`Scanner.DiscoverAsync`, ~1 s): for each address, an ICMP ping and TCP probes to `Ports.DiscoveryProbes` run at the same time. A TCP connection that is *refused* also counts as alive. After all probes, the OS **ARP cache** (`ArpTable`) is read. The probes make the OS ARP-resolve every local address, so devices that ignore ping and TCP still show up, and MAC addresses come from there.
- **Pass 2** ([DeepScanner.cs](src/NetScan/DeepScanner.cs), ~12 s):
  - *Per address, only for addresses pass 1 didn't find:* 3 ping attempts, TCP probes on the common ports plus extra consumer-device ports (sent in batches of 10 to limit the number of open sockets), and on Windows explicit ARP requests (`ActiveArp` → `SendARP`, which blocks, so the thread-pool minimum is raised).
  - *Across the whole range, at the same time:* mDNS, SSDP and NetBIOS queries sent over UDP, whose replies also fill in names for pass-1 hosts. Packet building and parsing is in [Protocols.cs](src/NetScan/Protocols.cs).
  - ARP, mDNS and SSDP only work on a directly attached subnet (`LocalNetwork.FindLocalAddressFor`). Remote targets get NetBIOS plus the per-address checks.
- **Watch** (`--watch <time>`, `WatchAsync` in Program.cs): repeats `DeepScanner.RunAsync` rounds (with a 5 s pause between them) until the time is up, printing each new device as it appears. It catches battery devices that only wake now and then. Rounds are tagged `pass = 3, 4, ...` through `HostSet.CurrentPass`, and `DiscoveredHost.FoundAfter` records when each host was first seen. While watching, the first Ctrl+C cancels only `watchCts` (the results are still printed). A second Ctrl+C cancels the main token.
- **Port scan** (`Scanner.ScanPortsAsync`): every (live host × port) pair, flattened into one work list.
- **Concurrency:** everything uses `Parallel.ForEachAsync` with `MaxDegreeOfParallelism = --threads` (max 255) over async I/O. "Threads" means probes in flight, not OS threads. Don't switch to one `Thread` per address.
- **ArpTable is platform-specific:** Windows uses a P/Invoke to `GetIpNetTable` (parses the raw 24-byte `MIB_IPNETROW` layout), Linux uses `/proc/net/arp`, and macOS/BSD run `arp -an`. It fails soft (an empty table) because ARP is a bonus source.
- **Auto-detected target** (`LocalNetwork`): the adapter that has a default gateway, narrowed to at most a /24. Explicit targets are capped at `IpRange.MaxHosts` (a /16).
- Progress is written to **stderr** so stdout stays clean for results.

## Notes

- `InternalsVisibleTo NetScan.Tests` exposes `internal` helpers (the ARP parsers, `Mdns.ReadName`) to tests.
- `ScannerTests` use real sockets on loopback (a `TcpListener`). Other tests are pure parsing tests. `ProtocolTests` build mDNS and NetBIOS responses by hand.
- Results vary between runs: phones and IoT devices sleep. The host name comes from reverse DNS first, then mDNS, then NetBIOS (`DisplayName`).
- Stale ARP cache entries can list a device that has recently left the network.
- On Linux/macOS, `Ping` may need raw-socket privileges or fall back to the system `ping` binary.
