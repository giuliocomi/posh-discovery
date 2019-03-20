function ActiveARP {
    <# 
    .SYNOPSIS 
    This script perform an ARP scan on a range of IPv4. The scope of this tool is to identify live hosts not enumerable via PingSweep method.
    
    .DESCRIPTION 
    Pretty fast and asynchronous ARP scanner to run on compromised Windows OS to further enumerate other live hosts that filter ICMP requests.
    
    .EXAMPLE 
    PS > ActiveARP -IPList $(CalculateRange -StartAddress 192.168.1.1 -EndAddress 192.168.1.255) 
    #> 

    [CmdletBinding(SupportsShouldProcess = $True)] Param(
        [parameter(Mandatory = $false, Position = 0)]
        [ValidatePattern("^\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b$")]
        [string[]]
        $IPList = @(),
        [parameter(Mandatory = $false, Position = 1)]
        [ValidatePattern("^\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b$")]
        [string]
        $StartAddress,
        [parameter(Mandatory = $false, Position = 2)]
        [ValidatePattern("^\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b$")]
        [string]
        $EndAddress
    )

    If ($StartAddress -and $EndAddress) {
        $IPList = $(CalculateRange -StartAddress $StartAddress -EndAddress $EndAddress)
    }

    $PortingARPCapability = @"
using System;
using System.Runtime.InteropServices;
using System.Net;
using System.Collections.Generic;
using System.Threading;

namespace ArpScanner
{
    public class ARPScan
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);
        static uint macAddrLen = (uint)new byte[6].Length;

        private static string MacAddresstoString(byte[] macAdrr)
        {
            string macString = BitConverter.ToString(macAdrr);
            return macString.ToUpper();
        }

        public static void ThreadedARPRequest(string ipString, List<Tuple<string, string>> result)
        {

            IPAddress ipAddress = new IPAddress(0);
            byte[] macAddr = new byte[6];

            try
            {
                ipAddress = IPAddress.Parse(ipString);

                SendARP((int)BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref macAddrLen);
                if (MacAddresstoString(macAddr) != "00-00-00-00-00-00")
                {
                	result.Add(new Tuple<string, string>(ipString, MacAddresstoString(macAddr)));
                }
            }
            catch { }
        }

        public static List<Tuple<string, string>> CheckStatus(string[] ipList)
        {
            List<Tuple<string, string>> result = new List<Tuple<string, string>>();
            byte[] macAddr = new byte[6];

            try
            {
                foreach (string ipString in ipList)
                {
                    Thread threadARP = new Thread(() => ThreadedARPRequest(ipString, result));
                    threadARP.Start();
                }
            }
            catch { }

            System.Threading.Thread.Sleep(4000);

            return result;
        }
    }
}
"@

	
    Add-Type -TypeDefinition $PortingARPCapability -Language CSharp
    $output = [ArpScanner.ARPScan]::CheckStatus($IPlist)
    $resultList = @()
    foreach ($entry in $output) {

        $resultEntry = New-Object PSObject
        $resultEntry | Add-Member -MemberType NoteProperty -Name "IP" -Value $entry.Item1
        $resultEntry | Add-Member -MemberType NoteProperty -Name "MAC" -Value $entry.Item2
        $resultList += $resultEntry
    }
    $resultList
}
