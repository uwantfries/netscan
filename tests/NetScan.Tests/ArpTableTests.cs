using System.Net;
using NetScan;

namespace NetScan.Tests;

public class ArpTableTests
{
    [Fact]
    public void Parses_linux_proc_arp()
    {
        const string text = """
            IP address       HW type     Flags       HW address            Mask     Device
            192.168.1.1      0x1         0x2         AA:BB:CC:00:11:22     *        eth0
            192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0
            192.168.1.20     0x1         0x2         10:20:30:40:50:60     *        eth0
            """;
        var table = ArpTable.ParseLinux(text);

        Assert.Equal(2, table.Count);
        Assert.Equal("aa:bb:cc:00:11:22", table[IPAddress.Parse("192.168.1.1")]);
        Assert.False(table.ContainsKey(IPAddress.Parse("192.168.1.9")));
    }

    [Fact]
    public void Parses_bsd_arp_command_and_skips_incomplete_and_multicast()
    {
        const string text = """
            ? (192.168.1.1) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]
            ? (192.168.1.7) at (incomplete) on en0 ifscope [ethernet]
            ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
            """;
        var table = ArpTable.ParseArpCommand(text);

        Assert.Single(table);
        Assert.Equal("00:1a:2b:3c:4d:5e", table[IPAddress.Parse("192.168.1.1")]);
    }
}
