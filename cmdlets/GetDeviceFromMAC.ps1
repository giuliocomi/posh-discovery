function GetDeviceFromMAC {
    <# 
    .SYNOPSIS 
    This script parses the MAC addresses from other scripts and resolve the corresponding device manufacturer information.
    
    .DESCRIPTION 
    This script parses the MAC addresses from other scripts and resolve the corresponding device manufacturer information.
    The MAC list properly formatted and ready-to-use is available here: https://github.com/giuliocomi/random/blob/master/maclist.txt
    
    .EXAMPLE 
    PS > GetDeviceFromMAC -InputFile ..\resources\maclist.txt -MAC DC-08-0F-01-DE-AC
    PS > PassiveARP -ResolveMAC | foreach {if($_.InterfaceDetails -ne "") {echo $_}}
     
    .LINK 
    http://standards-oui.ieee.org/oui/oui.txt
    
    .NOTES 
    This script is normally intended to be used with the PassiveARP and ActivaARP scanners to provide valueable information about the devices discovered:
    #> 
    [CmdletBinding()] Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MAC,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$InputFile
    )
    
    [string]$result = Select-String -Path $InputFile -Pattern $([regex]::Match($MAC, '^([0-9A-F]{2}-){2}([0-9A-F]{1})'))
    if (![string]::IsNullOrEmpty($result)) {
        echo $result.Split("|")[1]
    }
    echo ""
}
