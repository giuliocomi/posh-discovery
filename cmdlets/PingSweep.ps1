function PingSweep {
    <#
    .SYNOPSIS
    PingSweep script to quickly enumerate the live hosts in a network.
    
    .DESCRIPTION
    Pretty fast and asynchronous PingSweep to identify live targets that answers to ICMP request packets.
    
    .EXAMPLE
    PS > PingSweep -IPList $(CalculateRange -StartAddress 192.168.1.1 -EndAddress 192.168.1.255) -Interval 50
    PS > PingSweep -StartAddress 192.168.1.1 -EndAddress 192.168.1.255
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
        $EndAddress,
        [int]
        $Interval = 20
    )
    
    Begin {
        $resultList = @() 
    
        If ($StartAddress -and $EndAddress) {
            $IPList = $(CalculateRange -StartAddress $StartAddress -EndAddress $EndAddress)
        }
    }  
        
    Process {
        foreach ($ip in $IPList) {
            $ping = New-Object System.Net.NetworkInformation.Ping;
            Register-ObjectEvent -InputObject $ping -SourceIdentifier "EventPing_$ip" -EventName "PingCompleted"
            [Void]$ping.SendPingAsync("$ip")
    
            Start-Sleep -Milliseconds $Interval
        }
    }
        
    End {    
        Get-Event -SourceIdentifier "EventPing_*" | ForEach { 
            if ($_.SourceEventArgs.Reply.Status -eq "Success") {
                $address = $_.SourceEventArgs.Reply.Address
                $ttl = $_.SourceEventArgs.Reply.Options.TTL
                    
                $entry = New-Object -TypeName PSObject
                $entry |  Add-Member -MemberType NoteProperty -Name "IP" -Value "$address"
                $entry |  Add-Member -MemberType NoteProperty -Name "TTL" -Value "$ttl"
                $resultList += $entry
            }
        }
    
        Get-Event -SourceIdentifier "EventPing_*" | Remove-Event
        Get-EventSubscriber -SourceIdentifier "EventPing_*" | Unregister-Event
            
        return $resultList
    }
}
