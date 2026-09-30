using System.Net;
using System.Runtime.InteropServices;

namespace NetScan;

/// <summary>
/// Sends an explicit ARP request ("who has 192.168.1.x?") and waits for the reply. Almost every device on
/// a LAN must answer ARP to be reachable at all, even ones that drop ping and TCP.
/// Windows only (SendARP). On Linux/macOS the kernel ARPs for every ping/TCP probe anyway, and the
/// ARP cache is read afterwards.
/// </summary>
public static class ActiveArp
{
    public static bool IsSupported => OperatingSystem.IsWindows();

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int macAddrLen);

    /// <summary>
    /// Blocks for up to a few seconds. Only call it for addresses on a directly attached subnet:
    /// for anything else Windows ARPs the gateway and returns the router's MAC.
    /// </summary>
    public static string? Request(IPAddress target, IPAddress source)
    {
        var mac = new byte[6];
        int length = mac.Length;
        // SendARP takes addresses as the raw network-order bytes reinterpreted as a uint.
        uint dst = BitConverter.ToUInt32(target.GetAddressBytes());
        uint src = BitConverter.ToUInt32(source.GetAddressBytes());
        try
        {
            return SendARP(dst, src, mac, ref length) == 0 && length == 6 ? ArpTable.FormatMac(mac) : null;
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
    }
}
