using System.Collections.Concurrent;
using System.Net;

namespace NetScan;

/// <summary>How a host was found. A host can be found several ways.</summary>
[Flags]
public enum Method
{
    None = 0,
    Ping = 1,
    Tcp = 2,
    /// <summary>Listed in the OS ARP cache after probing.</summary>
    Arp = 4,
    /// <summary>Answered an explicit ARP request (pass 2, Windows).</summary>
    ArpRequest = 8,
    Mdns = 16,
    Ssdp = 32,
    NetBios = 64,
}

public sealed class DiscoveredHost(IPAddress address)
{
    private static readonly (Method Method, string Label)[] Labels =
    [
        (Method.Ping, "ping"), (Method.Tcp, "tcp"), (Method.Arp, "arp"), (Method.ArpRequest, "arp-req"),
        (Method.Mdns, "mdns"), (Method.Ssdp, "ssdp"), (Method.NetBios, "netbios"),
    ];

    private int _methods;
    private readonly List<int> _openPorts = [];

    public IPAddress Address { get; } = address;
    public uint SortKey { get; } = IpRange.ToUInt32(address);

    public Method Methods => (Method)Volatile.Read(ref _methods);
    public long? RoundTripMs { get; set; }
    public string? Mac { get; set; }
    public string? HostName { get; set; }
    public string? MdnsName { get; set; }
    public string? NetBiosName { get; set; }
    public bool IsLocalMachine { get; set; }
    /// <summary>1 = quick pass, 2 = deep pass, 3+ = a later watch round.</summary>
    public int Pass { get; init; } = 1;
    /// <summary>Time from the start of the scan until the host was first seen.</summary>
    public TimeSpan FoundAfter { get; init; }

    public string? DisplayName => HostName ?? MdnsName ?? NetBiosName;

    public string FoundBy => string.Join(",", Labels.Where(l => Methods.HasFlag(l.Method)).Select(l => l.Label));

    public void Add(Method method) => Interlocked.Or(ref _methods, (int)method);

    public IReadOnlyList<int> OpenPorts
    {
        get { lock (_openPorts) return [.. _openPorts.Order()]; }
    }

    public void AddOpenPort(int port)
    {
        lock (_openPorts) _openPorts.Add(port);
    }
}

/// <summary>The live hosts found so far in one target range. Safe to update from many probes at once.</summary>
public sealed class HostSet(IpRange range)
{
    private readonly ConcurrentDictionary<IPAddress, DiscoveredHost> _hosts = new();
    private readonly System.Diagnostics.Stopwatch _clock = System.Diagnostics.Stopwatch.StartNew();

    public IpRange Range { get; } = range;
    public int Count => _hosts.Count;

    /// <summary>Pass number given to hosts added from now on.</summary>
    public int CurrentPass { get; set; } = 1;

    public bool Contains(IPAddress address) => _hosts.ContainsKey(address);

    public DiscoveredHost? Find(IPAddress address) => _hosts.GetValueOrDefault(address);

    /// <summary>Records that <paramref name="address"/> answered; ignores addresses outside the range.</summary>
    public DiscoveredHost? Record(IPAddress address, Method method)
    {
        if (!Range.Contains(address)) return null;
        var host = _hosts.GetOrAdd(address, a => new DiscoveredHost(a) { Pass = CurrentPass, FoundAfter = _clock.Elapsed });
        host.Add(method);
        return host;
    }

    public void MergeArpCache()
    {
        foreach (var (ip, mac) in ArpTable.Read())
        {
            if (Record(ip, Method.Arp) is { } host)
                host.Mac ??= mac;
        }
    }

    public void MarkLocalMachine()
    {
        var local = LocalNetwork.LocalAddresses();
        foreach (var host in _hosts.Values)
            host.IsLocalMachine = local.Contains(host.Address);
    }

    public List<DiscoveredHost> Sorted() => [.. _hosts.Values.OrderBy(h => h.SortKey)];
}
