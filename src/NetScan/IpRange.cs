using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace NetScan;

/// <summary>An inclusive range of IPv4 host addresses to scan.</summary>
public sealed class IpRange
{
    /// <summary>Largest range accepted (a /16), to stop typos like /8 from scanning 16 million hosts.</summary>
    public const int MaxHosts = 65536;

    public uint First { get; }
    public uint Last { get; }
    public string Description { get; }
    public int Count => (int)(Last - First + 1);

    private IpRange(uint first, uint last, string description)
    {
        First = first;
        Last = last;
        Description = description;
    }

    /// <summary>
    /// Parses "192.168.1.0/24", "192.168.1.10-50", "192.168.1.10-192.168.1.50" or a single address.
    /// For CIDR blocks of /30 or wider the network and broadcast addresses are excluded.
    /// </summary>
    public static bool TryParse(string text, out IpRange range, out string error)
    {
        range = null!;
        error = "";
        text = text.Trim();

        int slash = text.IndexOf('/');
        if (slash >= 0)
        {
            if (!TryParseIPv4(text[..slash], out uint ip) ||
                !int.TryParse(text[(slash + 1)..], out int prefix) || prefix is < 0 or > 32)
            {
                error = $"'{text}' is not a valid CIDR block (expected e.g. 192.168.1.0/24).";
                return false;
            }
            return TryCreate(FromCidr(ip, prefix), text, out range, out error);
        }

        int dash = text.IndexOf('-');
        if (dash >= 0)
        {
            string left = text[..dash], right = text[(dash + 1)..];
            if (!TryParseIPv4(left, out uint first))
            {
                error = $"'{left}' is not a valid IPv4 address.";
                return false;
            }

            uint last;
            if (byte.TryParse(right, out byte lastOctet))
                last = (first & 0xFFFFFF00) | lastOctet;
            else if (!TryParseIPv4(right, out last))
            {
                error = $"'{right}' is not a valid IPv4 address or last octet.";
                return false;
            }

            if (last < first)
            {
                error = $"Range '{text}' ends before it starts.";
                return false;
            }
            return TryCreate((first, last), text, out range, out error);
        }

        if (TryParseIPv4(text, out uint single))
            return TryCreate((single, single), text, out range, out error);

        error = $"'{text}' is not an IPv4 address, range or CIDR block.";
        return false;
    }

    public static IpRange Parse(string text) =>
        TryParse(text, out var range, out var error) ? range : throw new FormatException(error);

    public static IpRange FromCidr(IPAddress address, int prefix)
    {
        uint ip = ToUInt32(address);
        var (first, last) = FromCidr(ip, prefix);
        return new IpRange(first, last, $"{ToAddress(ip & Mask(prefix))}/{prefix}");
    }

    public IEnumerable<IPAddress> Addresses()
    {
        for (ulong i = First; i <= Last; i++)
            yield return ToAddress((uint)i);
    }

    public bool Contains(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetwork && ToUInt32(address) is var ip && ip >= First && ip <= Last;

    public override string ToString() => Description;

    public static uint ToUInt32(IPAddress address) =>
        BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());

    public static IPAddress ToAddress(uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return new IPAddress(bytes);
    }

    private static uint Mask(int prefix) => prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);

    private static (uint First, uint Last) FromCidr(uint ip, int prefix)
    {
        uint network = ip & Mask(prefix);
        uint broadcast = network | ~Mask(prefix);
        return prefix <= 30 ? (network + 1, broadcast - 1) : (network, broadcast);
    }

    private static bool TryCreate((uint First, uint Last) bounds, string description, out IpRange range, out string error)
    {
        range = null!;
        error = "";
        if ((ulong)bounds.Last - bounds.First + 1 > MaxHosts)
        {
            error = $"'{description}' covers too many addresses (max {MaxHosts}, i.e. a /16).";
            return false;
        }
        range = new IpRange(bounds.First, bounds.Last, description);
        return true;
    }

    private static bool TryParseIPv4(string text, out uint value)
    {
        value = 0;
        // IPAddress.TryParse accepts shorthand like "10" or "1.2"; insist on dotted quad.
        if (text.Count(c => c == '.') != 3 ||
            !IPAddress.TryParse(text, out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork)
            return false;
        value = ToUInt32(address);
        return true;
    }
}
