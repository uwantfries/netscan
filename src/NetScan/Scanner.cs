using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;

namespace NetScan;

public sealed class Scanner(ScanOptions options)
{
    /// <summary>
    /// Pass 1 (quick): probes every address in hosts.Range with one ping and a few TCP connections at the
    /// same time (up to options.Threads hosts in flight), then adds hosts found only in the ARP cache.
    /// </summary>
    public async Task DiscoverAsync(HostSet hosts, IProgress<int>? progress, CancellationToken ct)
    {
        int done = 0;

        await Parallel.ForEachAsync(hosts.Range.Addresses(), Parallelism(ct), async (ip, token) =>
        {
            var ping = PingAsync(ip, options.TimeoutMs, token);
            var tcp = TcpAnswersAsync(ip, Ports.DiscoveryProbes, options.TimeoutMs, token);
            await Task.WhenAll(ping, tcp);

            if (ping.Result is { } rtt)
                hosts.Record(ip, Method.Ping)!.RoundTripMs = rtt;
            if (tcp.Result)
                hosts.Record(ip, Method.Tcp);
            progress?.Report(Interlocked.Increment(ref done));
        });

        hosts.MergeArpCache();
        hosts.MarkLocalMachine();
    }

    /// <summary>Phase 2: checks every (host, port) pair, up to options.Threads connections in flight.</summary>
    public async Task ScanPortsAsync(IReadOnlyList<DiscoveredHost> hosts, IProgress<int>? progress, CancellationToken ct)
    {
        var work = hosts.SelectMany(h => options.Ports.Select(p => (Host: h, Port: p)));
        int done = 0;

        await Parallel.ForEachAsync(work, Parallelism(ct), async (item, token) =>
        {
            if (await TcpProbe.ConnectAsync(item.Host.Address, item.Port, options.TimeoutMs, token) == TcpState.Open)
                item.Host.AddOpenPort(item.Port);
            progress?.Report(Interlocked.Increment(ref done));
        });
    }

    /// <summary>Reverse DNS for each host (via the OS resolver, which may also use NetBIOS / mDNS).</summary>
    public async Task ResolveNamesAsync(IReadOnlyList<DiscoveredHost> hosts, CancellationToken ct)
    {
        var limit = TimeSpan.FromMilliseconds(Math.Max(options.TimeoutMs * 2, 2000));
        await Parallel.ForEachAsync(hosts, Parallelism(ct), async (host, token) =>
        {
            try
            {
                var entry = await Dns.GetHostEntryAsync(host.Address).WaitAsync(limit, token);
                if (entry.HostName != host.Address.ToString())
                    host.HostName = entry.HostName;
            }
            catch (Exception e) when (e is System.Net.Sockets.SocketException or TimeoutException or ArgumentException)
            {
                // No name registered, or the lookup was too slow.
            }
        });
    }

    internal ParallelOptions Parallelism(CancellationToken ct) =>
        new() { MaxDegreeOfParallelism = options.Threads, CancellationToken = ct };

    /// <summary>Round-trip time in ms, or null if there was no echo reply.</summary>
    internal static async Task<long?> PingAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
    {
        using var ping = new Ping();
        try
        {
            var reply = await ping.SendPingAsync(ip, TimeSpan.FromMilliseconds(timeoutMs), null, null, ct);
            return reply.Status == IPStatus.Success ? reply.RoundtripTime : null;
        }
        catch (PingException)
        {
            return null;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;
        }
    }

    /// <summary>True as soon as any of the ports accepts or refuses a connection.</summary>
    internal static async Task<bool> TcpAnswersAsync(IPAddress ip, IEnumerable<int> ports, int timeoutMs, CancellationToken ct)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var pending = ports
            .Select(port => TcpProbe.ConnectAsync(ip, port, timeoutMs, stop.Token))
            .ToList();
        try
        {
            while (pending.Count > 0)
            {
                var finished = await Task.WhenAny(pending);
                pending.Remove(finished);
                if (await finished != TcpState.NoResponse)
                    return true;
            }
            return false;
        }
        finally
        {
            // Cancel the remaining probes and wait for them so their sockets are closed before we return.
            stop.Cancel();
            try { await Task.WhenAll(pending); } catch (OperationCanceledException) { }
        }
    }
}
