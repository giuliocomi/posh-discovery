function PassiveARP {
    <#
    .EXAMPLE
    PS > PassiveARP -ResolveMAC
    PS > PassiveARP -ResolveMAC | foreach {if($_.InterfaceDetails -ne "") {echo $_}}
    #>
    
    [CmdletBinding()] Param(
        [parameter(Mandatory = $false, Position = 0)]
        [switch]
        $ResolveMAC,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $InputFile
    )
    
    $resultList = @()
    Get-NetNeighbor | Foreach-Object {
        $entry = New-Object -TypeName psobject;
        $deviceFromMac = ""
    
        $entry | Add-Member -MemberType NoteProperty -Name "IP" -Value $_.IPAddress;
        $entry | Add-Member -MemberType NoteProperty -Name "MAC" -Value $_.LinkLayerAddress;
        $entry | Add-Member -MemberType NoteProperty -Name "InterfaceDetails" -Value $deviceFromMac
    
        if ($ResolveMAC) {
            if (($_.LinkLayerAddress -ne "00-00-00-00-00-00") -and -not [string]::IsNullOrEmpty($_.LinkLayerAddress) ) {
                $deviceFromMac = $_.LinkLayerAddress | GetDeviceFromMAC -InputFile $InputFile
            }
    
            $entry.InterfaceDetails = "$deviceFromMac"        
        }
    
        if ($entry.MAC -ne "00-00-00-00-00-00") {
            $resultList += $entry
        }
    }
    return $resultList
}
