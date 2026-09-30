using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetScan;

public static class LocalNetwork
{
    /// <summary>Widest subnet scanned automatically; larger LANs are narrowed to the /24 around this machine.</summary>
    public const int SmallestAutoPrefix = 24;

    /// <summary>
    /// The IPv4 subnet of the active network adapter (the one with a default gateway), or null if none.
    /// </summary>
    public static (IpRange Range, IPAddress LocalAddress, string Adapter)? FindDefaultSubnet()
    {
        var candidates =
            from nic in NetworkInterface.GetAllNetworkInterfaces()
            where nic.OperationalStatus == OperationalStatus.Up
               && nic.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
            let props = nic.GetIPProperties()
            let hasGateway = props.GatewayAddresses.Any(g =>
                g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any))
            from unicast in props.UnicastAddresses
            where unicast.Address.AddressFamily == AddressFamily.InterNetwork
               && !IPAddress.IsLoopback(unicast.Address)
               && !unicast.Address.ToString().StartsWith("169.254.") // link-local: no DHCP lease
            orderby hasGateway descending
            select (nic, unicast);

        var best = candidates.FirstOrDefault();
        if (best.nic is null) return null;

        int prefix = Math.Max(best.unicast.PrefixLength, SmallestAutoPrefix);
        return (IpRange.FromCidr(best.unicast.Address, prefix), best.unicast.Address, best.nic.Name);
    }

    /// <summary>
    /// This machine's address on the subnet that contains the whole range, or null if the range is not
    /// directly attached (link-local tricks such as ARP, mDNS and SSDP only work on an attached subnet).
    /// </summary>
    public static IPAddress? FindLocalAddressFor(IpRange range)
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                .Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(u.Address))
                .Where(u =>
                {
                    var subnet = IpRange.FromCidr(u.Address, u.PrefixLength);
                    return range.First >= subnet.First - 1 && range.Last <= subnet.Last + 1;
                })
                .Select(u => u.Address)
                .FirstOrDefault();
        }
        catch (NetworkInformationException)
        {
            return null;
        }
    }

    public static HashSet<IPAddress> LocalAddresses()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                .Select(u => u.Address)
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .ToHashSet();
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }
}
