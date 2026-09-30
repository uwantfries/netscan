using System.Net;
using System.Net.Sockets;

namespace NetScan;

/// <summary>
/// Pass 2: slower checks for devices that pass 1 missed (phones in power-saving mode, firewalled PCs,
/// IoT gear that ignores ping). Two kinds of check run at the same time:
///  - Per-address, only for addresses not found yet: ping retries, TCP probes on many more ports with a
///    longer timeout, and (Windows) explicit ARP requests with a retry.
///  - Broadcast-style listeners across the whole range: mDNS, SSDP and NetBIOS. Their replies also give
///    names for hosts found in pass 1.
/// </summary>
public sealed class DeepScanner(ScanOptions options)
{
    private const int PingAttempts = 3;
    private const int ArpAttempts = 2;
    /// <summary>Ports tried at once per address, to keep the total number of open sockets bounded.</summary>
    private const int TcpBatchSize = 10;
    /// <summary>How long listeners keep waiting after the last query, for slow responders.</summary>
    private static readonly TimeSpan LateReplyWindow = TimeSpan.FromSeconds(2);

    /// <summary>Extra ports that are open on common consumer devices but aren't in the default port list.</summary>
    private static readonly int[] ExtraProbePorts =
    [
        7000,   // AirPlay (Apple TV, HomePod, recent Macs)
        8008, 8009, // Chromecast / Google Home
        1400,   // Sonos
        49152, 49153, // UPnP devices
        5555,   // Android debug bridge (Fire TV, Android TV)
        32400,  // Plex
        8888, 9000, 10001, 5060, 1080, 8081, 8123, // misc web UIs, SIP, Home Assistant
    ];

    private int DeepTimeoutMs => Math.Max(2000, options.TimeoutMs * 2);

    /// <summary>
    /// Runs one deep round. Hosts found are tagged with <paramref name="pass"/> (2 for the deep pass,
    /// 3+ for watch rounds). Returns how many hosts this round added.
    /// </summary>
    public async Task<int> RunAsync(HostSet hosts, IProgress<int>? progress, CancellationToken ct, int pass = 2)
    {
        int before = hosts.Count;
        hosts.CurrentPass = pass;
        var range = hosts.Range;
        var remaining = range.Addresses().Where(a => !hosts.Contains(a)).ToList();
        IPAddress? local = LocalNetwork.FindLocalAddressFor(range);

        using var stopListening = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var listeners = new List<Task> { NetBiosAsync(hosts, local, stopListening.Token) };
        if (local is not null)
        {
            listeners.Add(MdnsAsync(hosts, local, stopListening.Token));
            listeners.Add(SsdpAsync(hosts, local, stopListening.Token));
        }

        bool useArp = local is not null && ActiveArp.IsSupported;
        if (useArp)
        {
            // SendARP blocks a thread for each request. Let the thread pool grow straight away instead of
            // adding threads slowly, which would serialize the ARP requests.
            ThreadPool.GetMinThreads(out int workers, out int io);
            ThreadPool.SetMinThreads(Math.Max(workers, options.Threads + 16), io);
        }

        var tcpPorts = Ports.Common.Keys.Concat(ExtraProbePorts).Distinct().ToArray();
        int done = 0;
        var perAddress = Parallel.ForEachAsync(remaining, new ParallelOptions
        {
            MaxDegreeOfParallelism = options.Threads,
            CancellationToken = ct,
        }, async (ip, token) =>
        {
            var ping = PingWithRetriesAsync(ip, token);
            var tcp = TcpInBatchesAsync(ip, tcpPorts, token);
            var arp = useArp ? Task.Run(() => ArpWithRetries(ip, local!), token) : Task.FromResult<string?>(null);
            await Task.WhenAll(ping, tcp, arp);

            if (ping.Result is { } rtt)
                hosts.Record(ip, Method.Ping)!.RoundTripMs = rtt;
            if (tcp.Result)
                hosts.Record(ip, Method.Tcp);
            if (arp.Result is { } mac)
                hosts.Record(ip, Method.ArpRequest)!.Mac ??= mac;
            progress?.Report(Interlocked.Increment(ref done));
        });

        // Give the listeners at least a few seconds even when there is little per-address work.
        await Task.WhenAll(perAddress, Task.Delay(TimeSpan.FromSeconds(4), ct));
        await Task.Delay(LateReplyWindow, ct);
        stopListening.Cancel();
        await Task.WhenAll(listeners);

        hosts.MergeArpCache();
        hosts.MarkLocalMachine();
        return hosts.Count - before;
    }

    private async Task<long?> PingWithRetriesAsync(IPAddress ip, CancellationToken ct)
    {
        for (int attempt = 0; attempt < PingAttempts; attempt++)
        {
            if (await Scanner.PingAsync(ip, DeepTimeoutMs, ct) is { } rtt)
                return rtt;
        }
        return null;
    }

    private async Task<bool> TcpInBatchesAsync(IPAddress ip, int[] ports, CancellationToken ct)
    {
        foreach (var batch in ports.Chunk(TcpBatchSize))
        {
            if (await Scanner.TcpAnswersAsync(ip, batch, DeepTimeoutMs, ct))
                return true;
        }
        return false;
    }

    private static string? ArpWithRetries(IPAddress ip, IPAddress local)
    {
        for (int attempt = 0; attempt < ArpAttempts; attempt++)
        {
            if (ActiveArp.Request(ip, local) is { } mac)
                return mac;
        }
        return null;
    }

    // ---- listeners ----

    private async Task NetBiosAsync(HostSet hosts, IPAddress? local, CancellationToken ct)
    {
        using var udp = OpenUdp(local);
        var receiving = ReceiveAllAsync(udp, (sender, packet) =>
        {
            var name = NetBios.ParseMachineName(packet);
            if (hosts.Record(sender, Method.NetBios) is { } host && name is not null)
                host.NetBiosName ??= name;
        }, ct);

        // Query every address, including pass-1 hosts, so they get names too.
        ushort id = 1;
        foreach (var ip in hosts.Range.Addresses())
        {
            await SendAsync(udp, NetBios.BuildNodeStatusQuery(id++), new IPEndPoint(ip, NetBios.Port), ct);
            if (id % 32 == 0) await Task.Delay(5, ct); // pace the burst a little
        }
        await receiving;
    }

    private async Task MdnsAsync(HostSet hosts, IPAddress local, CancellationToken ct)
    {
        using var udp = OpenUdp(local, multicast: true);
        var receiving = ReceiveAllAsync(udp, (sender, packet) =>
        {
            var name = Mdns.ParseHostName(packet, sender);
            if (hosts.Record(sender, Method.Mdns) is { } host && name is not null)
                host.MdnsName ??= name;
        }, ct);

        var services = Mdns.BuildQuery(Mdns.ServicesName, Mdns.TypePtr);
        await SendAsync(udp, services, Mdns.Group, ct);
        // Reverse lookups: "who is 192.168.1.x?" to the group, one per address.
        foreach (var ip in hosts.Range.Addresses())
            await SendAsync(udp, Mdns.BuildQuery(Mdns.ReverseName(ip), Mdns.TypePtr), Mdns.Group, ct);
        await Task.Delay(1000, ct).ContinueWith(_ => { }, TaskScheduler.Default);
        await SendAsync(udp, services, Mdns.Group, ct);
        await receiving;
    }

    private async Task SsdpAsync(HostSet hosts, IPAddress local, CancellationToken ct)
    {
        using var udp = OpenUdp(local, multicast: true);
        var receiving = ReceiveAllAsync(udp, (sender, _) => hosts.Record(sender, Method.Ssdp), ct);

        // UDP is lossy and devices answer at random within MX seconds, so ask a few times.
        for (int i = 0; i < 3 && !ct.IsCancellationRequested; i++)
        {
            await SendAsync(udp, Ssdp.SearchAll, Ssdp.Group, ct);
            await Task.Delay(1000, ct).ContinueWith(_ => { }, TaskScheduler.Default);
        }
        await receiving;
    }

    private static UdpClient OpenUdp(IPAddress? local, bool multicast = false)
    {
        var udp = new UdpClient(new IPEndPoint(local ?? IPAddress.Any, 0));
        if (OperatingSystem.IsWindows())
        {
            // Stop an ICMP "port unreachable" from a host with the port closed from surfacing as an error
            // on the next receive.
            const int SioUdpConnReset = -1744830452;
            udp.Client.IOControl(SioUdpConnReset, [0, 0, 0, 0], null);
        }
        if (multicast && local is not null)
            udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, local.GetAddressBytes());
        return udp;
    }

    private static async Task SendAsync(UdpClient udp, byte[] packet, IPEndPoint target, CancellationToken ct)
    {
        try
        {
            await udp.SendAsync(packet, target, ct);
        }
        catch (SocketException)
        {
            // e.g. no route; the other checks still run.
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static async Task ReceiveAllAsync(UdpClient udp, Action<IPAddress, byte[]> handle, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await udp.ReceiveAsync(ct);
                handle(result.RemoteEndPoint.Address, result.Buffer);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (SocketException)
            {
                // A stray ICMP error on some platforms; keep listening.
            }
        }
    }
}
