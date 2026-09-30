namespace NetScan;

/// <summary>A single-line progress counter on stderr, so stdout stays clean for the results.</summary>
public sealed class ConsoleProgress(string label, int total) : IProgress<int>
{
    private readonly bool _enabled = !Console.IsErrorRedirected;
    private readonly Lock _lock = new();
    private long _lastWrite;

    public void Report(int value)
    {
        if (!_enabled) return;
        long now = Environment.TickCount64;
        lock (_lock)
        {
            if (value < total && now - _lastWrite < 100) return;
            _lastWrite = now;
            Console.Error.Write($"\r{label}: {value}/{total} ({value * 100 / Math.Max(total, 1)}%)   ");
        }
    }

    public void Clear()
    {
        if (!_enabled) return;
        lock (_lock)
            Console.Error.Write("\r" + new string(' ', label.Length + 30) + "\r");
    }
}
