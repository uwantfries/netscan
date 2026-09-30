namespace NetScan;

public sealed class ScanOptions
{
    public const int MaxThreads = 255;

    /// <summary>Target from the command line; null means "the local subnet".</summary>
    public string? Target { get; set; }
    public int Threads { get; set; } = MaxThreads;
    public int TimeoutMs { get; set; } = 1000;
    public int[] Ports { get; set; } = [.. NetScan.Ports.Common.Keys.Order()];
    public bool ScanPorts { get; set; } = true;
    public bool ResolveNames { get; set; } = true;
    /// <summary>Run the slower second discovery pass (ARP requests, mDNS, SSDP, NetBIOS, retries).</summary>
    public bool DeepScan { get; set; } = true;
    /// <summary>Keep re-checking addresses not found yet for this long, to catch devices that sleep.</summary>
    public TimeSpan? Watch { get; set; }
    public static readonly TimeSpan MaxWatch = TimeSpan.FromHours(24);
    public bool ShowHelp { get; set; }

    public const string Usage = """
        Usage: netscan [target] [options]

        Finds devices on a network, then checks which common ports are open on each.
          Pass 1 (quick): one ping and a few TCP probes per address, plus the ARP cache.
          Pass 2 (deep):  for addresses not found yet, ping retries, many more TCP ports
                          and ARP requests; mDNS, SSDP and NetBIOS queries across the range.
          Watch:          repeats pass 2 until the time is up (--watch), to catch
                          devices that only wake now and then (battery sensors, phones).

        Target (default: the local subnet):
          192.168.1.0/24              CIDR block
          192.168.1.10-50             range within the last octet
          192.168.1.10-192.168.1.50   full range
          192.168.1.20                single address

        Options:
          -t, --threads <n>     Concurrent probes, 1-255 (default 255)
          -w, --timeout <ms>    Timeout per ping / connection attempt (default 1000)
          -p, --ports <list>    Ports to check, e.g. 22,80,443,8000-8100 (default: common ports)
              --no-ports        Only find devices; skip the port scan
              --quick           Skip pass 2 (faster, but finds fewer devices)
              --watch <time>    Keep looking for new devices for this long, e.g. 5m, 90s, 1h
                                (a plain number means minutes). Ctrl+C stops watching early
                                and still shows the results.
              --no-dns          Don't look up host names
          -h, --help            Show this help
        """;

    public static bool TryParse(string[] args, out ScanOptions options, out string error)
    {
        options = new ScanOptions();
        error = "";

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            switch (arg)
            {
                case "-h" or "--help" or "-?" or "/?":
                    options.ShowHelp = true;
                    break;
                case "-t" or "--threads":
                    if (!TryInt(args, ref i, 1, MaxThreads, out int threads, out error)) return false;
                    options.Threads = threads;
                    break;
                case "-w" or "--timeout":
                    if (!TryInt(args, ref i, 50, 60_000, out int timeout, out error)) return false;
                    options.TimeoutMs = timeout;
                    break;
                case "-p" or "--ports":
                    if (!TryValue(args, ref i, out string list, out error)) return false;
                    if (!NetScan.Ports.TryParseList(list, out int[] ports, out error)) return false;
                    options.Ports = ports;
                    break;
                case "--no-ports":
                    options.ScanPorts = false;
                    break;
                case "--quick":
                    options.DeepScan = false;
                    break;
                case "--watch":
                    if (!TryValue(args, ref i, out string duration, out error)) return false;
                    if (!TryParseDuration(duration, out var watch) || watch <= TimeSpan.Zero || watch > MaxWatch)
                    {
                        error = $"'{duration}' is not a valid watch time (e.g. 90s, 5m, 1h; max 24h).";
                        return false;
                    }
                    options.Watch = watch;
                    break;
                case "--no-dns":
                    options.ResolveNames = false;
                    break;
                default:
                    if (arg.StartsWith('-'))
                    {
                        error = $"Unknown option '{arg}'.";
                        return false;
                    }
                    if (options.Target is not null)
                    {
                        error = $"Only one target may be given (got '{options.Target}' and '{arg}').";
                        return false;
                    }
                    options.Target = arg;
                    break;
            }
        }
        return true;
    }

    /// <summary>Parses "90s", "5m", "1.5h" or a plain number of minutes.</summary>
    public static bool TryParseDuration(string text, out TimeSpan duration)
    {
        duration = TimeSpan.Zero;
        text = text.Trim().ToLowerInvariant();
        if (text.Length == 0) return false;

        (string number, double secondsPerUnit) = text[^1] switch
        {
            's' => (text[..^1], 1.0),
            'm' => (text[..^1], 60.0),
            'h' => (text[..^1], 3600.0),
            _ => (text, 60.0),
        };
        if (!double.TryParse(number, System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out double value) || !double.IsFinite(value))
            return false;
        duration = TimeSpan.FromSeconds(value * secondsPerUnit);
        return true;
    }

    private static bool TryValue(string[] args, ref int i, out string value, out string error)
    {
        value = "";
        error = "";
        if (i + 1 >= args.Length)
        {
            error = $"Option '{args[i]}' needs a value.";
            return false;
        }
        value = args[++i];
        return true;
    }

    private static bool TryInt(string[] args, ref int i, int min, int max, out int value, out string error)
    {
        value = 0;
        string option = args[i];
        if (!TryValue(args, ref i, out string text, out error)) return false;
        if (!int.TryParse(text, out value) || value < min || value > max)
        {
            error = $"Option '{option}' must be a number from {min} to {max}.";
            return false;
        }
        return true;
    }
}
