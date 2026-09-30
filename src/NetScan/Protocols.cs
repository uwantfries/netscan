using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace NetScan;

/// <summary>
/// mDNS / Bonjour (UDP 5353). Queries are sent to the multicast group from an ordinary port
/// ("legacy unicast"), so devices reply straight to us. Apple devices, Chromecasts, printers, smart
/// speakers and most Linux boxes answer.
/// </summary>
public static class Mdns
{
    public static readonly IPEndPoint Group = new(IPAddress.Parse("224.0.0.251"), 5353);
    public const ushort TypeA = 1;
    public const ushort TypePtr = 12;

    /// <summary>"Which services exist?": every device advertising any service answers.</summary>
    public const string ServicesName = "_services._dns-sd._udp.local";

    /// <summary>"4.1.168.192.in-addr.arpa": asks the owner of 192.168.1.4 for its name.</summary>
    public static string ReverseName(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return $"{b[3]}.{b[2]}.{b[1]}.{b[0]}.in-addr.arpa";
    }

    public static byte[] BuildQuery(string name, ushort type)
    {
        var packet = new List<byte>(12 + name.Length + 6);
        packet.AddRange(new byte[] { 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 }); // id 0, flags 0, 1 question
        foreach (var label in name.Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            packet.Add((byte)bytes.Length);
            packet.AddRange(bytes);
        }
        packet.Add(0);
        packet.AddRange(new byte[] { (byte)(type >> 8), (byte)type, 0, 1 }); // class IN
        return [.. packet];
    }

    /// <summary>
    /// The sender's host name from a response: an A record pointing at the sender, or a reverse PTR
    /// record for the sender's address. Null if the packet has neither or is malformed.
    /// </summary>
    public static string? ParseHostName(byte[] packet, IPAddress sender)
    {
        try
        {
            int questions = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4));
            int records = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6))
                        + BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(8))
                        + BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(10));
            int pos = 12;
            for (int i = 0; i < questions; i++)
            {
                ReadName(packet, ref pos);
                pos += 4;
            }

            string reverse = ReverseName(sender);
            for (int i = 0; i < records; i++)
            {
                string owner = ReadName(packet, ref pos);
                ushort type = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(pos));
                int length = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(pos + 8));
                int data = pos + 10;
                pos = data + length;

                if (type == TypeA && length == 4 && packet.AsSpan(data, 4).SequenceEqual(sender.GetAddressBytes()))
                    return owner;
                if (type == TypePtr && owner.Equals(reverse, StringComparison.OrdinalIgnoreCase))
                    return ReadName(packet, ref data);
            }
        }
        catch (Exception e) when (e is ArgumentOutOfRangeException or IndexOutOfRangeException or InvalidDataException)
        {
            // Truncated or malformed packet.
        }
        return null;
    }

    /// <summary>Reads a DNS name, following compression pointers.</summary>
    internal static string ReadName(byte[] packet, ref int pos)
    {
        var labels = new List<string>();
        int cursor = pos;
        bool jumped = false;
        for (int jumps = 0; ; )
        {
            int length = packet[cursor];
            if (length == 0)
            {
                cursor++;
                break;
            }
            if ((length & 0xC0) == 0xC0)
            {
                if (++jumps > 16) throw new InvalidDataException("DNS name pointer loop");
                if (!jumped) pos = cursor + 2;
                jumped = true;
                cursor = ((length & 0x3F) << 8) | packet[cursor + 1];
                continue;
            }
            labels.Add(Encoding.UTF8.GetString(packet, cursor + 1, length));
            cursor += 1 + length;
        }
        if (!jumped) pos = cursor;
        return string.Join('.', labels);
    }
}

/// <summary>
/// NetBIOS node status (UDP 137): asks a host for its NetBIOS name table. Windows PCs, Samba servers and
/// NAS boxes answer with their computer name. Works across routers because it is plain unicast.
/// </summary>
public static class NetBios
{
    public const int Port = 137;

    public static byte[] BuildNodeStatusQuery(ushort transactionId)
    {
        var packet = new byte[50];
        BinaryPrimitives.WriteUInt16BigEndian(packet, transactionId);
        packet[5] = 1;     // 1 question
        packet[12] = 0x20; // encoded name length
        // The wildcard name "*" padded with NULs, in NetBIOS "first-level" encoding (each nibble + 'A').
        var name = new byte[16];
        name[0] = (byte)'*';
        for (int i = 0; i < 16; i++)
        {
            packet[13 + i * 2] = (byte)('A' + (name[i] >> 4));
            packet[14 + i * 2] = (byte)('A' + (name[i] & 0xF));
        }
        packet[47] = 0x21; // type NBSTAT
        packet[49] = 0x01; // class IN
        return packet;
    }

    /// <summary>The machine name (the unique name with suffix 0x00) from a node status response.</summary>
    public static string? ParseMachineName(byte[] packet)
    {
        const int countOffset = 56; // header 12 + name 34 + type 2 + class 2 + ttl 4 + length 2
        if (packet.Length <= countOffset) return null;

        int count = packet[countOffset];
        string? fallback = null;
        for (int i = 0; i < count; i++)
        {
            int entry = countOffset + 1 + i * 18;
            if (entry + 18 > packet.Length) break;
            string name = Encoding.ASCII.GetString(packet, entry, 15).TrimEnd(' ', '\0');
            byte suffix = packet[entry + 15];
            bool isGroup = (packet[entry + 16] & 0x80) != 0;
            if (suffix == 0 && !isGroup && name.Length > 0) return name;
            fallback ??= name.Length > 0 ? name : null;
        }
        return fallback;
    }
}

/// <summary>SSDP / UPnP discovery (UDP 1900): smart TVs, routers, media servers, consoles and speakers answer.</summary>
public static class Ssdp
{
    public static readonly IPEndPoint Group = new(IPAddress.Parse("239.255.255.250"), 1900);

    public static readonly byte[] SearchAll = Encoding.ASCII.GetBytes(
        "M-SEARCH * HTTP/1.1\r\n" +
        "HOST: 239.255.255.250:1900\r\n" +
        "MAN: \"ssdp:discover\"\r\n" +
        "MX: 2\r\n" +
        "ST: ssdp:all\r\n\r\n");
}
