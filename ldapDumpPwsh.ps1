<#
.SYNOPSIS
  LDAP Enumeration Script using paged (chunked) queries to avoid OOM.

.DESCRIPTION
  This script connects to a specified LDAP path and enumerates objects
  (users, groups, computers, etc.) with “chunks” to avoid overload of mem.

.PARAMETER LDAPPath
  LDAP path, include DN. Ex:
    LDAP://<ip>/DC=example,DC=com

.PARAMETER Username
  Username "DOMAIN\foo" ou "foo@domain".

.PARAMETER Password
  Password.

.PARAMETER AuthType
 Type of auth .NET, Ex:
    [System.DirectoryServices.AuthenticationTypes]::Secure
    [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer

.NOTES
   Requirements.. Windows PowerShell and .NET Framework with System.DirectoryServices
#>

Param(
    [string]$LDAPPath = "LDAP://<ip>/DC=<example>,DC=<com>",
    [string]$Username = "", # DOMAIN\JOHNDOE
    [string]$Password = "",
    [System.DirectoryServices.AuthenticationTypes]$AuthType = [System.DirectoryServices.AuthenticationTypes]::Secure,
    [string]$OutputPath = ".\"
)

Write-Host "[*] Connecting to: $LDAPPath"
Write-Host "[*] Using Credentials: $Username"
Write-Host "[*] Authentication Type: $AuthType"


try {
    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($LDAPPath, $Username, $Password, $AuthType)
    $DirectoryEntry.RefreshCache()
    Write-Host "[+] Successfully connected to LDAP!"
} catch {
    Write-Host "[-] Failed to connect to LDAP server: $($_.Exception.Message)" -ForegroundColor Red
    return
}


function Export-LDAPSearchChunked {
    param (
        [string]$Filter,
        [string[]]$Properties,
        [scriptblock]$Transform,
        [string]$CsvFile,
        [int]$PageSize = 500
    )

    
    $FullPath = Join-Path $OutputPath $CsvFile
    if (Test-Path $FullPath) {
        Remove-Item $FullPath -Force
    }

    
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry)
    $Searcher.Filter = $Filter
    
    $Searcher.PageSize = $PageSize 
    $Searcher.PropertiesToLoad.AddRange($Properties)

    Write-Host "[*] Querying LDAP with filter: $Filter - PageSize=$PageSize"

    
    $Results = $null
    try {
        $Results = $Searcher.FindAll()
    } catch {
        Write-Host "[-] Error in LDAP query: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    
    if (-not $Results) {
        Write-Host "[-] No results found for '$Filter'."
        return
    }

    
    $ChunkSize = 500
    $ChunkArray = @()

    $Count = 0
    foreach ($Result in $Results) {
        $Count++
        
        $Entry = $Result.GetDirectoryEntry()
        $Obj = & $Transform $Entry
        if ($Obj -ne $null) {
            $ChunkArray += $Obj
        }

        
        if ($ChunkArray.Count -ge $ChunkSize) {
            if (Test-Path $FullPath) {
                $ChunkArray | Export-Csv -Path $FullPath -NoTypeInformation -Append -Encoding UTF8
            } else {
                $ChunkArray | Export-Csv -Path $FullPath -NoTypeInformation -Encoding UTF8
            }
            $ChunkArray = @()
        }
    }

    if ($ChunkArray.Count -gt 0) {
        if (Test-Path $FullPath) {
            $ChunkArray | Export-Csv -Path $FullPath -NoTypeInformation -Append -Encoding UTF8
        } else {
            $ChunkArray | Export-Csv -Path $FullPath -NoTypeInformation -Encoding UTF8
        }
        $ChunkArray = @()
    }

    Write-Host "[+] Total of $Count results exported to $FullPath"
    # Free MEM :P
    $Results.Dispose()
}


Export-LDAPSearchChunked `
    -Filter "(objectClass=group)" `
    -Properties @("cn","description","member") `
    -CsvFile "domain_groups.csv" `
    -Transform {
        param($Entry)
        [PSCustomObject]@{
            "GroupName"   = $Entry.Properties["cn"][0]
            "Description" = $Entry.Properties["description"][0]
            "Members"     = ($Entry.Properties["member"] -join "; ")
        }
    }


Export-LDAPSearchChunked `
    -Filter "(&(objectClass=user)(!(objectClass=computer)))" `
    -Properties @("cn","mail","lastLogonTimestamp","userAccountControl") `
    -CsvFile "domain_users.csv" `
    -Transform {
        param($Entry)
        
        [PSCustomObject]@{
            "UserName"             = $Entry.Properties["cn"][0]
            "Email"                = $Entry.Properties["mail"][0]
            "LastLogon"            = $Entry.Properties["lastLogonTimestamp"][0]
            "AccountDisabled"      = ($Entry.Properties["userAccountControl"][0] -band 2 -ne 0)
            "PasswordNeverExpires" = ($Entry.Properties["userAccountControl"][0] -band 65536 -ne 0)
        }
    }


Export-LDAPSearchChunked `
    -Filter "(objectClass=computer)" `
    -Properties @("cn","operatingSystem","lastLogonTimestamp") `
    -CsvFile "domain_computers.csv" `
    -Transform {
        param($Entry)
        [PSCustomObject]@{
            "ComputerName"   = $Entry.Properties["cn"][0]
            "OperatingSystem"= $Entry.Properties["operatingSystem"][0]
            "LastLogon"      = $Entry.Properties["lastLogonTimestamp"][0]
        }
    }


Export-LDAPSearchChunked `
    -Filter "(objectClass=domainDNS)" `
    -Properties @("minPwdLength","maxPwdAge","lockoutThreshold") `
    -CsvFile "domain_policy.csv" `
    -Transform {
        param($Entry)
        [PSCustomObject]@{
            "MinPasswordLength" = $Entry.Properties["minPwdLength"][0]
            "MaxPasswordAge"    = $Entry.Properties["maxPwdAge"][0]
            "LockoutThreshold"  = $Entry.Properties["lockoutThreshold"][0]
        }
    }

Write-Host ""
Write-Host "[+] LDAP Enumeration Completed with paged queries!" -ForegroundColor Green
