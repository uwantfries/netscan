using System.Net;
using System.Net.Sockets;

namespace NetScan;

public enum TcpState
{
    /// <summary>Connection accepted: something is listening.</summary>
    Open,
    /// <summary>Connection actively refused: the host exists but the port is closed.</summary>
    Refused,
    /// <summary>No answer before the timeout (host down, or packets dropped by a firewall).</summary>
    NoResponse,
}

public static class TcpProbe
{
    public static async Task<TcpState> ConnectAsync(IPAddress address, int port, int timeoutMs, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(timeoutMs);
        using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), timeout.Token);
            return TcpState.Open;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return TcpState.Refused;
        }
        catch (SocketException)
        {
            return TcpState.NoResponse;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return TcpState.NoResponse;
        }
    }
}
