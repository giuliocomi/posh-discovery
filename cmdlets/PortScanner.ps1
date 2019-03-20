function PortScan {
    <# 
    .SYNOPSIS 
    This script performs TCP or UDP scans of target network.
     
    .DESCRIPTION 
    CalculateRange is a very convenient way to create a list made of continous IPv4 addresses.
    THe output is a list that is easy to use as input for other scripts like ARPScanner, PortScanner, etc.
    
    .EXAMPLE 
    PS > PortScan -ListeningIP 192.168.1.50 -IPList $(CalculateRange -StartAddress 192.168.1.1 -EndAddress 192.168.4.255) -TCP -PortList 22,80,8080,445,5940,5531 -Interval 1200
    #>  

    [CmdletBinding(SupportsShouldProcess = $True)] Param(
        [parameter(Mandatory = $false, Position = 0)]
        [ValidatePattern("^\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b$")]
        [string]
        $ListeningIP,
        [parameter(Mandatory = $false, Position = 1)]
        [ValidatePattern("^\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b$")]
        [string[]]
        $IPList = @(),
        [parameter(Mandatory = $false, Position = 2)]
        [ValidatePattern("^\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b$")]
        [string]
        $StartAddress,
        [parameter(Mandatory = $false, Position = 3)]
        [ValidatePattern("^\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b$")]
        [string]
        $EndAddress,
        [parameter(Mandatory = $false, Position = 4)]
        [ValidatePattern("^\b\d+\b$")]
        [int[]]
        $PortList,
        [parameter(Mandatory = $false, Position = 5)]
        [switch]
        $UDP,
        [parameter(Mandatory = $false, Position = 6)]
        [switch]
        $TCP,
        [parameter(Mandatory = $false, Position = 7)]
        [int]
        $Interval
    )

    If ($StartAddress -and $EndAddress) {
        $IPList = $(CalculateRange -StartAddress $StartAddress -EndAddress $EndAddress)
    }

    $PortingARPCapability = @"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
namespace PortScanner
{
public class PortScanner
{
public static Dictionary<Tuple<string, int, string>, bool> portResult = new Dictionary<Tuple<string, int, string>, bool>(); //ip, port, protocol, status

public static Dictionary<Tuple<string, int, string>, bool> StartScanner(string stringIPListening, List<string> ipTargets, List<int> portToScan, string protocolType, int interval)
{
IPAddress ipListening = null;
List<IPAddress> ipAddresses = new List<IPAddress>();
ipListening = IPAddress.Parse(stringIPListening);

foreach (string ipString in ipTargets)
{
    ipAddresses.Add(IPAddress.Parse(ipString));
}

Thread threadedPacketListener = new Thread(() => new PacketListener(ipListening, ipAddresses).Start());
threadedPacketListener.Start();

switch (protocolType)
{
    case "UDP":
        Thread threadedUDPScanner = new Thread(() => new UDPScanner(ipAddresses, portToScan, interval).Start());
        threadedUDPScanner.Start();
        threadedUDPScanner.Join();
        break;
    default:
        Thread threadedTCPScanner = new Thread(() => new TCPScanner(ipAddresses, portToScan, interval).Start());
        threadedTCPScanner.Start();
        threadedTCPScanner.Join();
        break;
}

threadedPacketListener.Join(); //wait that the listener is down to prepare the output

Thread threadedFillPortStatus = new Thread(() => Helper.FillPortStatus(ref portResult, ipTargets, portToScan, protocolType)); //fill in the output before overwriting the existing entry with the results from the PacketListener
threadedFillPortStatus.Start();
threadedFillPortStatus.Join();

return portResult;
}
private class UDPScanner
{
private readonly List<IPAddress> targets = new List<IPAddress>();
private readonly List<int> ports = new List<int>();
private readonly int interval;

public UDPScanner(List<IPAddress> targets, List<int> ports, int interval=1000)
{
    this.targets = targets;
    this.ports = ports;
    this.interval = interval;
}

private void UDPProbePort(IPAddress ipAddress, int port)
{
    byte[] bytes = ipAddress.GetAddressBytes();
    var endPoint = new IPEndPoint(BitConverter.ToUInt32(bytes, 0), port);
    var udpClient = new UdpClient();
    udpClient.Connect(endPoint);
    udpClient.SendAsync(System.Text.Encoding.ASCII.GetBytes(""), System.Text.Encoding.ASCII.GetBytes("").Length);
    udpClient.Close();
}

private void UDPScanPortList(IPAddress ipAddress, List<int> ports)
{
    foreach (var port in ports)
        UDPProbePort(ipAddress, port);
}
public void Start()
{
    Parallel.ForEach(this.targets, target => { UDPScanPortList(target, this.ports); Thread.Sleep(interval); }); ; //delay 1000ms for linux machines because there is set a frequency limit to icmp responses
}
}
private class TCPScanner
{
private readonly List<IPAddress> tcpTargets = new List<IPAddress>();
private readonly List<int> tcpPorts = new List<int>();
private readonly int interval;

public TCPScanner(List<IPAddress> targets, List<int> ports, int interval=20)
{
    this.tcpTargets = targets;
    this.tcpPorts = ports;
    this.interval = interval;
}
private static void ConnectCallback(IAsyncResult ar) { /*empty*/ }

private void TCPProbePort(IPAddress ipAddress, int tcpPort)
{
    Socket client = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
    IPEndPoint endopointDetails = new IPEndPoint(ipAddress, tcpPort);
    client.BeginConnect(endopointDetails, new AsyncCallback(ConnectCallback), client);
    Thread.Sleep(interval);
    client.Close(); //free the socket otherwise it gets saturated...
}
private void TCPScanPortList(IPAddress ipAddress, List<int> tcpPorts)
{
    Parallel.ForEach(tcpPorts, tcpPort => TCPProbePort(ipAddress, tcpPort));
}
public void Start()
{
    Parallel.ForEach(this.tcpTargets, target => { TCPScanPortList(target, this.tcpPorts); Thread.Sleep(interval); });
}
}
private class PacketListener
{
private readonly Dictionary<int, string> protocolMap = new Dictionary<int, string>() { { 1, "ICMP" }, { 6, "TCP" }, { 17, "UDP" } };
private readonly IPAddress ipInterface;
private readonly List<IPAddress> ipTargets;
public PacketListener(IPAddress ipInterface, List<IPAddress> ipTargets)
{
    this.ipInterface = ipInterface;
    this.ipTargets = ipTargets;
}
public void Start()
{
    Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
    socket.Bind(new IPEndPoint(ipInterface, 0));
    socket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), null);
    byte[] buffer = new byte[90];
    Tuple<string, int, string> entry = new Tuple<string, int, string>("", 0, "");

    Action<IAsyncResult> ParseIncomingPacket = null;
    ParseIncomingPacket = (ar) =>
    {
        int protocolType = buffer[9]; // type of protocol over IPv4 (ICMP, TCP, UDP, ...)
        if (ipTargets.Contains(new IPAddress(BitConverter.ToUInt32(buffer, 12)))) //only parse in-scope packets
        {
            if (protocolType == 1 && buffer[20] == 3 && buffer[21] == 3) //ICMP type "Destination Unreachable" code "Port Unreachable" are generated by the target OS and are the clue of UDP port closed
            {
                entry = new Tuple<string, int, string>(new IPAddress(BitConverter.ToUInt32(buffer, 12)).ToString(), (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 50)), "UDP");
                if (!portResult.ContainsKey(entry))
                    portResult.Add(entry, false);
            }
            if (protocolType == 6) //TCP
            {
                int flag = buffer[33]; //position of the flag info inside a TCP packet
                switch (buffer[33].ToString("X"))
                {
                    case "12":
                        entry = new Tuple<string, int, string>(
                        new IPAddress(BitConverter.ToUInt32(buffer, 12)).ToString(), //target address
                        (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 20)), //target port
                        "TCP");
                        if (!portResult.ContainsKey(entry))
                            portResult.Add(entry, true); //port open detected
                        break;
                    case "14":
                        entry = new Tuple<string, int, string>(
                        new IPAddress(BitConverter.ToUInt32(buffer, 12)).ToString(),
                        (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 20)),
                        "TCP");
                        if (!portResult.ContainsKey(entry))
                            portResult.Add(entry, false); //port close detected
                        break;
                    default:
                        break;
                }
            }
            buffer = new byte[90];
        }
        //keeps listening
        socket.BeginReceive(buffer, 0, 90, SocketFlags.None, new AsyncCallback(ParseIncomingPacket), null);
    };
    // begin listening to the socket
    socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(ParseIncomingPacket), null);
    Console.WriteLine("Press enter to stop the packet listener");
    Console.Read(); //keep the listener alive until the input from the user
}
}
}
static class Helper
{
internal static void FillPortStatus(ref Dictionary<Tuple<string, int, string>, bool> portResult, List<string> ipTargets, List<int> portToScan, string protocolType)
{
bool defaultStatus = false;
List<Tuple<string, int, string, bool>> portOutput = new List<Tuple<string, int, string, bool>>();
foreach (var ip in ipTargets)
{
    foreach (var port in portToScan)
    {
        if (protocolType == "TCP")
        {
            defaultStatus = false; //for TCP by default we assume that a port is closed && for UDP we assume that a port by default is open/filtered
        }
        else
        {
            defaultStatus = true;
        }
        if (!portResult.ContainsKey(new Tuple<string, int, string>(ip, port, protocolType)))
            portResult.Add(new Tuple<string, int, string>(ip, port, protocolType), defaultStatus);
    }
}
return;
}
}
}
"@

    Add-Type -TypeDefinition $PortingARPCapability -Language CSharp

    if ($UDP) {
        $ProtocolType = "UDP"
        $Interval = 1000
    }
    else {
        $ProtocolType = "TCP"
        $Interval = 20
    }

    $output = [PortScanner.PortScanner]::StartScanner($ListeningIP, $IPList, $PortList, $ProtocolType, $Interval)
    $resultList = @()
    foreach ($entry in $output) {

        $resultEntry = New-Object PSObject
        $resultEntry | Add-Member -MemberType NoteProperty -Name "IP" -Value $entry.Item1
        $resultEntry | Add-Member -MemberType NoteProperty -Name "Port" -Value $entry.Item2
        $resultEntry | Add-Member -MemberType NoteProperty -Name "Protocol" -Value $entry.Item3
        $resultEntry | Add-Member -MemberType NoteProperty -Name "PortStatus" -Value $entry.Item4
        $resultList += $resultEntry
    }
    $resultList
}

