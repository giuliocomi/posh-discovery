Get-ChildItem $PSScriptRoot | ? { $_.PSIsContainer -and ($_.Name -ne 'maclist.txt') } | % { Import-Module $_.FullName -DisableNameChecking }
