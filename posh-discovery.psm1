Get-ChildItem . | ? {  ($_.Name -ne 'maclist.txt') } | % { Import-Module $_.FullName -DisableNameChecking }
