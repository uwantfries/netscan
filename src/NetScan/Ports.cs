namespace NetScan;

public static class Ports
{
    /// <summary>Ports checked on every live host unless --ports is given.</summary>
    public static readonly IReadOnlyDictionary<int, string> Common = new Dictionary<int, string>
    {
        [21] = "ftp",
        [22] = "ssh",
        [23] = "telnet",
        [25] = "smtp",
        [53] = "dns",
        [80] = "http",
        [110] = "pop3",
        [135] = "msrpc",
        [139] = "netbios",
        [143] = "imap",
        [443] = "https",
        [445] = "smb",
        [515] = "lpd",
        [548] = "afp",
        [554] = "rtsp",
        [631] = "ipp",
        [993] = "imaps",
        [995] = "pop3s",
        [1883] = "mqtt",
        [1900] = "upnp",
        [3306] = "mysql",
        [3389] = "rdp",
        [5000] = "upnp/http",
        [5432] = "postgres",
        [5900] = "vnc",
        [8000] = "http-alt",
        [8080] = "http-proxy",
        [8443] = "https-alt",
        [8883] = "mqtts",
        [9100] = "printer",
        [62078] = "iphone-sync",
    };

    /// <summary>
    /// Ports used during discovery: a host that accepts or actively refuses a connection on any of
    /// these is alive even if it ignores ping.
    /// </summary>
    public static readonly int[] DiscoveryProbes = [80, 443, 22, 445, 139, 3389, 8080, 62078];

    public static string NameOf(int port) => Common.TryGetValue(port, out var name) ? name : "";

    /// <summary>Parses a list such as "22,80,8000-8010" into sorted, distinct port numbers.</summary>
    public static bool TryParseList(string text, out int[] ports, out string error)
    {
        ports = [];
        error = "";
        var result = new SortedSet<int>();

        foreach (var part in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int dash = part.IndexOf('-');
            string lowText = dash < 0 ? part : part[..dash];
            string highText = dash < 0 ? part : part[(dash + 1)..];

            if (!int.TryParse(lowText, out int low) || !int.TryParse(highText, out int high) ||
                low is < 1 or > 65535 || high is < 1 or > 65535 || high < low)
            {
                error = $"'{part}' is not a valid port or port range (1-65535).";
                return false;
            }
            for (int p = low; p <= high; p++)
                result.Add(p);
        }

        if (result.Count == 0)
        {
            error = "No ports given.";
            return false;
        }
        ports = [.. result];
        return true;
    }
}
