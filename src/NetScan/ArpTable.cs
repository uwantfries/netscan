using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace NetScan;

/// <summary>
/// Reads the operating system's ARP cache (IP → MAC address). Pinging or connecting to a host on the
/// local subnet makes the OS resolve its MAC first, so after discovery the cache also lists devices that
/// answered ARP but ignored the ping and TCP probes.
/// </summary>
public static partial class ArpTable
{
    public static IReadOnlyDictionary<IPAddress, string> Read()
    {
        try
        {
            if (OperatingSystem.IsWindows()) return ReadWindows();
            if (OperatingSystem.IsLinux()) return ParseLinux(File.ReadAllText("/proc/net/arp"));
            if (OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD()) return ParseArpCommand(RunArpCommand());
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or DllNotFoundException
                                      or EntryPointNotFoundException or System.ComponentModel.Win32Exception)
        {
            // ARP is a bonus source; the scan still works without it.
        }
        return new Dictionary<IPAddress, string>();
    }

    // ---- Windows: GetIpNetTable from iphlpapi.dll ----

    [DllImport("iphlpapi.dll")]
    private static extern int GetIpNetTable(IntPtr table, ref int size, bool sort);

    private const int ErrorInsufficientBuffer = 122;
    private const int RowSize = 24; // MIB_IPNETROW: index, physAddrLen, physAddr[8], addr, type
    private const int TypeInvalid = 2;

    private static Dictionary<IPAddress, string> ReadWindows()
    {
        var result = new Dictionary<IPAddress, string>();
        int size = 0;
        int status = GetIpNetTable(IntPtr.Zero, ref size, false);

        // The table can grow between the size query and the read, so retry a few times.
        for (int attempt = 0; attempt < 3 && status == ErrorInsufficientBuffer; attempt++)
        {
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                status = GetIpNetTable(buffer, ref size, false);
                if (status != 0) continue;

                int count = Marshal.ReadInt32(buffer);
                for (int i = 0; i < count; i++)
                {
                    IntPtr row = buffer + 4 + i * RowSize;
                    int macLength = Marshal.ReadInt32(row, 4);
                    int type = Marshal.ReadInt32(row, 20);
                    if (type == TypeInvalid || macLength != 6) continue;

                    var mac = new byte[6];
                    Marshal.Copy(row + 8, mac, 0, 6);
                    var ip = new byte[4];
                    Marshal.Copy(row + 16, ip, 0, 4);
                    Add(result, new IPAddress(ip), mac);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return result;
    }

    // ---- Linux: /proc/net/arp ----

    /// <summary>Parses /proc/net/arp: "IP address  HW type  Flags  HW address  Mask  Device".</summary>
    internal static Dictionary<IPAddress, string> ParseLinux(string text)
    {
        var result = new Dictionary<IPAddress, string>();
        foreach (var line in text.Split('\n').Skip(1))
        {
            var cols = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (cols.Length < 4 || cols[2] == "0x0") continue; // 0x0 = incomplete
            if (IPAddress.TryParse(cols[0], out var ip) && TryParseMac(cols[3], out var mac))
                Add(result, ip, mac);
        }
        return result;
    }

    // ---- macOS / BSD: `arp -an` ----

    private static string RunArpCommand()
    {
        using var process = Process.Start(new ProcessStartInfo("arp", "-an")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        })!;
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit(5000);
        return output;
    }

    /// <summary>Parses lines like "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]".</summary>
    internal static Dictionary<IPAddress, string> ParseArpCommand(string text)
    {
        var result = new Dictionary<IPAddress, string>();
        foreach (Match m in ArpLine().Matches(text))
        {
            if (IPAddress.TryParse(m.Groups[1].Value, out var ip) && TryParseMac(m.Groups[2].Value, out var mac))
                Add(result, ip, mac);
        }
        return result;
    }

    [GeneratedRegex(@"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)")]
    private static partial Regex ArpLine();

    // ---- shared ----

    private static bool TryParseMac(string text, out byte[] mac)
    {
        mac = new byte[6];
        var parts = text.Split(':', '-');
        if (parts.Length != 6) return false;
        for (int i = 0; i < 6; i++)
        {
            // macOS drops leading zeros ("0:1a:..."), so accept 1-2 hex digits.
            if (!byte.TryParse(parts[i], System.Globalization.NumberStyles.HexNumber, null, out mac[i]))
                return false;
        }
        return true;
    }

    private static void Add(Dictionary<IPAddress, string> result, IPAddress ip, byte[] mac)
    {
        if (FormatMac(mac) is { } text)
            result[ip] = text;
    }

    /// <summary>"aa:bb:cc:dd:ee:ff", or null for incomplete (all zero), broadcast and multicast addresses.</summary>
    internal static string? FormatMac(byte[] mac) =>
        mac.All(b => b == 0) || (mac[0] & 1) == 1 ? null : string.Join(':', mac.Select(b => b.ToString("x2")));
}
