function CalculateRange {
    <# 
    .SYNOPSIS 
    This script generates a range of IPv4.
     
    .DESCRIPTION 
    CalculateRange is a very convenient way to create a list made of continous IPv4 addresses.
    THe output is a list that is easy to use as input for other scripts like ARPScanner, PortScanner, etc.
    
    .EXAMPLE 
    PS > CalculateRange -StartAddress 192.168.1.1 -EndAddress 192.168.50.128
    #>  
    [CmdletBinding()] Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidatePattern("^\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b$")]
        [string]
        $StartAddress,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidatePattern("^\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b$")]
        [string]
        $EndAddress
    )    
            
    # snippet from https://github.com/samratashok/nishang/blob/master/Scan/Invoke-PortScan.ps1
    $list = @()
    foreach ($a in ($StartAddress.Split(".")[0]..$EndAddress.Split(".")[0])) {
        foreach ($b in ($StartAddress.Split(".")[1]..$EndAddress.Split(".")[1])) {
            foreach ($c in ($StartAddress.Split(".")[2]..$EndAddress.Split(".")[2])) {
                foreach ($d in ($StartAddress.Split(".")[3]..$EndAddress.Split(".")[3])) {
                    $list += "$a.$b.$c.$d"
                }
            }
        }
    } 
    return $list
}
