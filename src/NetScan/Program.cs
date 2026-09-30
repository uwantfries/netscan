using System.Diagnostics;
using NetScan;

if (!ScanOptions.TryParse(args, out var options, out var error))
{
    Console.Error.WriteLine($"netscan: {error}");
    Console.Error.WriteLine("Run 'netscan --help' for usage.");
    return 2;
}
if (options.ShowHelp)
{
    Console.WriteLine(ScanOptions.Usage);
    return 0;
}

IpRange range;
if (options.Target is not null)
{
    if (!IpRange.TryParse(options.Target, out range, out error))
    {
        Console.Error.WriteLine($"netscan: {error}");
        return 2;
    }
}
else
{
    var local = LocalNetwork.FindDefaultSubnet();
    if (local is null)
    {
        Console.Error.WriteLine("netscan: no active IPv4 network adapter found; give a target such as 192.168.1.0/24.");
        return 2;
    }
    range = local.Value.Range;
    Console.WriteLine($"Local network: {local.Value.Adapter}, this machine is {local.Value.LocalAddress}");
}

using var cts = new CancellationTokenSource();
// While watching, the first Ctrl+C only ends the watch (results are still shown); the next one cancels all.
using var watchCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
bool watching = false;
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    if (watching && !watchCts.IsCancellationRequested)
        watchCts.Cancel();
    else
        cts.Cancel();
};

var scanner = new Scanner(options);
var clock = Stopwatch.StartNew();
Console.WriteLine($"Scanning {range} ({range.Count} addresses, {options.Threads} at a time, {options.TimeoutMs} ms timeout)...");

try
{
    var found = new HostSet(range);
    var discoverProgress = new ConsoleProgress("Pass 1: finding devices", range.Count);
    await scanner.DiscoverAsync(found, discoverProgress, cts.Token);
    discoverProgress.Clear();
    Console.WriteLine($"Pass 1 (quick) found {found.Count} device(s) in {clock.Elapsed.TotalSeconds:0.0}s.");

    if (options.DeepScan)
    {
        var passClock = Stopwatch.StartNew();
        int remaining = range.Count - found.Count;
        var deepProgress = new ConsoleProgress($"Pass 2: deep checks on {remaining} remaining addresses", remaining);
        int added = await new DeepScanner(options).RunAsync(found, deepProgress, cts.Token);
        deepProgress.Clear();
        Console.WriteLine($"Pass 2 (deep) found {added} more in {passClock.Elapsed.TotalSeconds:0.0}s, {found.Count} in total.");
    }

    if (options.Watch is { } watchFor)
    {
        watching = true;
        await WatchAsync(found, watchFor, options, watchCts.Token);
        watching = false;
        cts.Token.ThrowIfCancellationRequested();
    }

    var hosts = found.Sorted();
    if (hosts.Count == 0)
        return 0;

    var nameLookup = options.ResolveNames ? scanner.ResolveNamesAsync(hosts, cts.Token) : Task.CompletedTask;

    if (options.ScanPorts)
    {
        var portProgress = new ConsoleProgress("Checking ports", hosts.Count * options.Ports.Length);
        await scanner.ScanPortsAsync(hosts, portProgress, cts.Token);
        portProgress.Clear();
    }
    await nameLookup;

    Console.WriteLine();
    PrintResults(hosts, options);
    Console.WriteLine();
    Console.WriteLine($"Done in {clock.Elapsed.TotalSeconds:0.0}s.");
    return 0;
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine();
    Console.Error.WriteLine("Cancelled.");
    return 130;
}

// Repeats deep rounds on the addresses not found yet until the time is up, reporting new devices as they appear.
static async Task WatchAsync(HostSet found, TimeSpan watchFor, ScanOptions options, CancellationToken ct)
{
    var roundPause = TimeSpan.FromSeconds(5);
    var deep = new DeepScanner(options);
    var clock = Stopwatch.StartNew();
    int startCount = found.Count, round = 0;
    ConsoleProgress? progress = null;

    Console.WriteLine($"Watching for new devices for {FormatDuration(watchFor)} (Ctrl+C to stop early and show results)...");
    try
    {
        while (clock.Elapsed < watchFor)
        {
            round++;
            int pass = 2 + round;
            int remaining = found.Range.Count - found.Count;
            progress = new ConsoleProgress(
                $"Watch round {round}, {found.Count} found, {FormatDuration(watchFor - clock.Elapsed)} left", remaining);
            await deep.RunAsync(found, progress, ct, pass);
            progress.Clear();
            PrintNewHosts(found, pass);

            var left = watchFor - clock.Elapsed;
            if (left > TimeSpan.Zero)
                await Task.Delay(left < roundPause ? left : roundPause, ct);
        }
    }
    catch (OperationCanceledException) when (ct.IsCancellationRequested)
    {
        // Ctrl+C: keep whatever the interrupted round found.
        progress?.Clear();
        found.MergeArpCache();
        PrintNewHosts(found, 2 + round);
        Console.WriteLine("Watch stopped.");
    }
    Console.WriteLine($"Watch found {found.Count - startCount} more in {round} round(s), {found.Count} in total.");
}

static void PrintNewHosts(HostSet found, int pass)
{
    foreach (var host in found.Sorted().Where(h => h.Pass == pass))
        Console.WriteLine($"  [{FormatDuration(host.FoundAfter)}] new device: {host.Address,-15} {host.Mac ?? "",-17} {host.FoundBy} {host.DisplayName}");
}

static string FormatDuration(TimeSpan t) =>
    t.TotalHours >= 1 ? $"{(int)t.TotalHours}h{t.Minutes:00}m" : $"{t.Minutes}:{t.Seconds:00}";

static void PrintResults(List<DiscoveredHost> hosts, ScanOptions options)
{
    int nameWidth = Math.Clamp(hosts.Max(h => h.DisplayName?.Length ?? 0), 4, 40);
    int foundByWidth = Math.Max(8, hosts.Max(h => h.FoundBy.Length));
    Console.WriteLine($"{"Address",-16} {"Name".PadRight(nameWidth)} {"MAC",-17} {"Found by".PadRight(foundByWidth)} {"Ping",6}");
    Console.WriteLine(new string('-', 16 + nameWidth + 17 + foundByWidth + 6 + 4));

    foreach (var host in hosts)
    {
        string name = host.DisplayName ?? "";
        if (name.Length > nameWidth) name = name[..(nameWidth - 1)] + "~";
        string rtt = host.RoundTripMs is { } ms ? $"{ms} ms" : "";
        string note = host.IsLocalMachine ? "  (this machine)"
            : host.Pass == 2 ? "  (pass 2)"
            : host.Pass > 2 ? $"  (watch, after {FormatDuration(host.FoundAfter)})"
            : "";
        Console.WriteLine($"{host.Address,-16} {name.PadRight(nameWidth)} {host.Mac ?? "",-17} {host.FoundBy.PadRight(foundByWidth)} {rtt,6}{note}");

        if (!options.ScanPorts) continue;
        var open = host.OpenPorts;
        if (open.Count == 0)
            Console.WriteLine("    no open ports found");
        foreach (int port in open)
            Console.WriteLine($"    {port + "/tcp",-10} {Ports.NameOf(port)}");
    }
}
