using System.Net;
using NetScan;

namespace NetScan.Tests;

public class IpRangeTests
{
    [Theory]
    [InlineData("192.168.1.0/24", "192.168.1.1", "192.168.1.254", 254)]
    [InlineData("192.168.1.77/24", "192.168.1.1", "192.168.1.254", 254)]
    [InlineData("10.0.0.0/30", "10.0.0.1", "10.0.0.2", 2)]
    [InlineData("10.0.0.4/31", "10.0.0.4", "10.0.0.5", 2)]
    [InlineData("10.0.0.9/32", "10.0.0.9", "10.0.0.9", 1)]
    [InlineData("192.168.1.10-50", "192.168.1.10", "192.168.1.50", 41)]
    [InlineData("192.168.1.250-192.168.2.5", "192.168.1.250", "192.168.2.5", 12)]
    [InlineData("172.16.0.5", "172.16.0.5", "172.16.0.5", 1)]
    public void Parses_valid_targets(string text, string first, string last, int count)
    {
        var range = IpRange.Parse(text);
        var addresses = range.Addresses().ToList();

        Assert.Equal(count, range.Count);
        Assert.Equal(count, addresses.Count);
        Assert.Equal(IPAddress.Parse(first), addresses[0]);
        Assert.Equal(IPAddress.Parse(last), addresses[^1]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("hello")]
    [InlineData("192.168.1")]
    [InlineData("192.168.1.0/33")]
    [InlineData("192.168.1.300")]
    [InlineData("192.168.1.50-10")]
    [InlineData("10.0.0.0/8")] // too large
    [InlineData("::1")]
    public void Rejects_invalid_targets(string text)
    {
        Assert.False(IpRange.TryParse(text, out _, out var error));
        Assert.NotEmpty(error);
    }

    [Fact]
    public void Contains_checks_bounds()
    {
        var range = IpRange.Parse("192.168.1.0/24");
        Assert.True(range.Contains(IPAddress.Parse("192.168.1.1")));
        Assert.False(range.Contains(IPAddress.Parse("192.168.1.255")));
        Assert.False(range.Contains(IPAddress.Parse("192.168.2.1")));
    }
}
