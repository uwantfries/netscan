using System.Net;
using System.Net.Sockets;
using NetScan;

namespace NetScan.Tests;

public class ScannerTests
{
    [Fact]
    public async Task TcpProbe_distinguishes_open_and_refused_ports()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int openPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        int closedPort = FreePort();

        Assert.Equal(TcpState.Open, await TcpProbe.ConnectAsync(IPAddress.Loopback, openPort, 2000, default));
        Assert.Equal(TcpState.Refused, await TcpProbe.ConnectAsync(IPAddress.Loopback, closedPort, 3000, default));
    }

    [Fact]
    public async Task Discovers_loopback_and_finds_its_open_port()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int openPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        var options = new ScanOptions { TimeoutMs = 2000, Ports = [openPort, FreePort()] };
        var scanner = new Scanner(options);

        var found = new HostSet(IpRange.Parse("127.0.0.1"));
        await scanner.DiscoverAsync(found, null, default);
        var hosts = found.Sorted();
        var host = Assert.Single(hosts);
        Assert.True(host.Methods.HasFlag(Method.Ping) || host.Methods.HasFlag(Method.Tcp));

        await scanner.ScanPortsAsync(hosts, null, default);
        Assert.Equal([openPort], host.OpenPorts);
    }

    private static int FreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        return ((IPEndPoint)l.LocalEndpoint).Port;
    }
}
