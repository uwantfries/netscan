using NetScan;

namespace NetScan.Tests;

public class OptionsTests
{
    [Fact]
    public void Defaults_scan_common_ports_with_255_threads()
    {
        Assert.True(ScanOptions.TryParse([], out var o, out _));
        Assert.Null(o.Target);
        Assert.Equal(255, o.Threads);
        Assert.True(o.ScanPorts);
        Assert.Contains(22, o.Ports);
        Assert.Contains(443, o.Ports);
    }

    [Fact]
    public void Parses_all_options()
    {
        Assert.True(ScanOptions.TryParse(
            ["10.0.0.0/24", "-t", "64", "--timeout", "300", "-p", "22,80,8000-8002", "--no-dns"],
            out var o, out _));
        Assert.Equal("10.0.0.0/24", o.Target);
        Assert.Equal(64, o.Threads);
        Assert.Equal(300, o.TimeoutMs);
        Assert.Equal([22, 80, 8000, 8001, 8002], o.Ports);
        Assert.False(o.ResolveNames);
    }

    [Theory]
    [InlineData("-t", "0")]
    [InlineData("-t", "256")]
    [InlineData("-p", "0")]
    [InlineData("-p", "70000")]
    [InlineData("-p", "90-80")]
    [InlineData("--bogus")]
    [InlineData("-t")]
    [InlineData("10.0.0.1", "10.0.0.2")]
    public void Rejects_bad_arguments(params string[] args)
    {
        Assert.False(ScanOptions.TryParse(args, out _, out var error));
        Assert.NotEmpty(error);
    }
}

public class WatchOptionTests
{
    [Theory]
    [InlineData("90s", 90)]
    [InlineData("5m", 300)]
    [InlineData("5", 300)]
    [InlineData("1.5h", 5400)]
    [InlineData("2M", 120)]
    public void Parses_watch_durations(string text, int seconds)
    {
        Assert.True(ScanOptions.TryParse(["--watch", text], out var o, out _));
        Assert.Equal(TimeSpan.FromSeconds(seconds), o.Watch);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-5m")]
    [InlineData("25h")]
    [InlineData("soon")]
    [InlineData("m")]
    public void Rejects_bad_watch_durations(string text)
    {
        Assert.False(ScanOptions.TryParse(["--watch", text], out _, out var error));
        Assert.NotEmpty(error);
    }

    [Fact]
    public void Watch_is_off_by_default()
    {
        Assert.True(ScanOptions.TryParse([], out var o, out _));
        Assert.Null(o.Watch);
    }
}
