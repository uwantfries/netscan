using System.Net;
using NetScan;

namespace NetScan.Tests;

public class ProtocolTests
{
    private static readonly IPAddress Phone = IPAddress.Parse("192.168.1.42");

    [Fact]
    public void Mdns_reverse_name_reverses_octets()
    {
        Assert.Equal("42.1.168.192.in-addr.arpa", Mdns.ReverseName(Phone));
    }

    [Fact]
    public void Mdns_query_round_trips_through_name_reader()
    {
        var packet = Mdns.BuildQuery(Mdns.ServicesName, Mdns.TypePtr);
        int pos = 12;
        Assert.Equal(Mdns.ServicesName, Mdns.ReadName(packet, ref pos));
        Assert.Equal(packet.Length - 4, pos);
        Assert.Equal([0, 12, 0, 1], packet[^4..]);
    }

    [Fact]
    public void Mdns_parses_reverse_ptr_answer()
    {
        // Response: 0 questions, 1 answer: <reverse name> PTR "Kims-iPhone.local"
        var packet = Response(Record(Mdns.ReverseName(Phone), Mdns.TypePtr, Name("Kims-iPhone.local")));
        Assert.Equal("Kims-iPhone.local", Mdns.ParseHostName(packet, Phone));
    }

    [Fact]
    public void Mdns_parses_a_record_for_sender_and_follows_compression()
    {
        var owner = Name("Living-Room.local");
        // Answer 1: unrelated PTR. Answer 2: A record whose owner is a pointer back to offset 12 (start of answer 1's owner).
        var first = Record("Living-Room.local", Mdns.TypePtr, Name("x.local"));
        var second = new List<byte> { 0xC0, 12 };
        second.AddRange(new byte[] { 0, 1, 0, 1, 0, 0, 0, 120, 0, 4 });
        second.AddRange(Phone.GetAddressBytes());
        var packet = Response(first, [.. second]);

        Assert.Equal("Living-Room.local", Mdns.ParseHostName(packet, Phone));
    }

    [Fact]
    public void Mdns_ignores_malformed_packets()
    {
        Assert.Null(Mdns.ParseHostName([0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 3], Phone));
        Assert.Null(Mdns.ParseHostName([], Phone));
    }

    [Fact]
    public void NetBios_query_encodes_wildcard_name()
    {
        var q = NetBios.BuildNodeStatusQuery(0x1234);
        Assert.Equal(50, q.Length);
        Assert.Equal(0x12, q[0]);
        Assert.Equal("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", System.Text.Encoding.ASCII.GetString(q, 13, 32));
        Assert.Equal(0x21, q[47]);
    }

    [Fact]
    public void NetBios_prefers_unique_workstation_name()
    {
        var packet = new byte[57 + 3 * 18];
        packet[56] = 3;
        WriteEntry(packet, 0, "WORKGROUP", 0x00, group: true);
        WriteEntry(packet, 1, "NAS-BOX", 0x20, group: false);
        WriteEntry(packet, 2, "NAS-BOX", 0x00, group: false);
        Assert.Equal("NAS-BOX", NetBios.ParseMachineName(packet));
        Assert.Null(NetBios.ParseMachineName(new byte[20]));
    }

    private static void WriteEntry(byte[] packet, int index, string name, byte suffix, bool group)
    {
        int at = 57 + index * 18;
        System.Text.Encoding.ASCII.GetBytes(name.PadRight(15)).CopyTo(packet, at);
        packet[at + 15] = suffix;
        packet[at + 16] = group ? (byte)0x80 : (byte)0;
    }

    private static byte[] Name(string name)
    {
        var bytes = new List<byte>();
        foreach (var label in name.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        bytes.Add(0);
        return [.. bytes];
    }

    private static byte[] Record(string owner, ushort type, byte[] data)
    {
        var bytes = new List<byte>(Name(owner));
        bytes.AddRange(new byte[] { 0, (byte)type, 0, 1, 0, 0, 0, 120, 0, (byte)data.Length });
        bytes.AddRange(data);
        return [.. bytes];
    }

    private static byte[] Response(params byte[][] answers)
    {
        var bytes = new List<byte> { 0, 0, 0x84, 0, 0, 0, 0, (byte)answers.Length, 0, 0, 0, 0 };
        foreach (var a in answers) bytes.AddRange(a);
        return [.. bytes];
    }
}
