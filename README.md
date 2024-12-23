LDAP Enumeration Script with Chunked Processing

This PowerShell script performs LDAP enumeration in chunks to efficiently query and export large datasets from an LDAP server without exhausting system memory ( LARGE DOMAIN ). It connects to an LDAP server, retrieves data (users, groups, computers, and domain policies), and exports the results incrementally to CSV files.

### Features
1.	Chunked Processing: Processes and exports data in manageable chunks to avoid OutOfMemoryException.
2.	Paged LDAP Queries: Leverages the PageSize property for efficient server-side querying.
3.	Modular Design: Allows customization for different LDAP queries via a single function.
4.	Export to CSV: Results are saved directly to CSV files, with support for incremental appends.
5.	Memory Efficiency: Automatically clears processed results and disposes of LDAP collections to minimize memory usage.
6.	Authentication Options: Supports secure LDAP connections with NTLM or LDAP Secure (LDAPS).
7.	Customizable Queries: Easily adapt filters and exported attributes to fit specific requirements.

### Requirements
•	PowerShell: Windows PowerShell 5.1 or later.
•	LDAP Access: Valid credentials with appropriate permissions to query the LDAP server.
•	.NET Framework: Ensure that the System.DirectoryServices library is available.

### Usage

1. Set Up the Script
	Save the script as ldap_enum.ps1.
2. Execute the Script
	Run the script from PowerShell with appropriate parameters:

.\ldap_enum.ps1 `
    -LDAPPath "LDAP://<ip>/DC=example,DC=net" `
    -Username "example\FOO" `
    -Password "Winter!123" `
    -OutputPath "C:\Temp\" `
    -AuthType ([System.DirectoryServices.AuthenticationTypes]::Secure)

3. Parameters
-	-LDAPPath: The LDAP server and distinguished name (DN). Examples:
-	LDAP://<ip>/DC=example,DC=net
-	LDAPS://<ip>:636/DC=example,DC=net (for LDAPS)
-	-Username: The username for LDAP authentication.
-	-Password: The password for the specified username.
-	-OutputPath: Directory where CSV files will be saved.
-	-AuthType: Authentication type. Common options include:
-	Secure (default)
-	SecureSocketsLayer (for LDAPS)

### Output

The script generates the following CSV files in the specified OutputPath:
1.	domain_groups.csv: Contains group names, descriptions, and members.
2.	domain_users.csv: Contains user names, emails, last logon timestamps, and account status.
3.	domain_computers.csv: Contains computer names, operating systems, and last logon timestamps.
4.	domain_policy.csv: Contains domain password policies (e.g., minimum length, max age, lockout thresholds).

Each file is generated incrementally in chunks to avoid memory overload.

### Example Outputs


#### Groups (domain_groups.csv)

GroupName	Description	Members
Domain Admins	Admins of the domain	user1; user2; user3
HR	Human Resources	user4; user5

#### Users (domain_users.csv)

UserName	Email	LastLogon	AccountDisabled	PasswordNeverExpires
john.doe	john@domain.com	2023-12-23 10:15	False	True

Computers (domain_computers.csv)

ComputerName	OperatingSystem	LastLogon
DC01	Windows Server 2022 Standard	2023-12-22 22:30

#### Policies (domain_policy.csv)

MinPasswordLength	MaxPasswordAge	LockoutThreshold
8	42 days	5 attempts

#### Limitations
1.	Chunk Size: Default chunk size is 500. This may need to be adjusted for very large directories.
2.	Export Format: Only CSV is supported.
3.	Custom Attributes: Only the attributes specified in the script are retrieved. Additional attributes must be manually added to the Properties parameter.
4.	No IP Resolution: The script does not resolve IPs for hosts. This can be added with DNS lookups if needed.
5.	LDAPS Dependency: If the LDAP server requires LDAPS, you must configure the -LDAPPath and -AuthType accordingly.

#### Customization

- Add New Queries

To add new queries, use the Export-LDAPSearchChunked function. For example:

```powershell
Export-LDAPSearchChunked
    -Filter "(objectClass=yourCustomClass)"
    -Properties @("attribute1", "attribute2")
    -CsvFile "custom_query.csv"
    -Transform {
        param($Entry)
        [PSCustomObject]@{
            "CustomAttribute1" = $Entry.Properties["attribute1"][0]
            "CustomAttribute2" = $Entry.Properties["attribute2"][0]
        }
    }

```

- Adjust Chunk Size

Modify the -PageSize parameter when calling Export-LDAPSearchChunked to control how many objects are processed at a time:

```powerhsell
-PageSize 100
```

### Troubleshooting

Error: “Failed to connect to LDAP server”
	•	Check the -LDAPPath format and ensure it points to a valid LDAP server.
	•	Ensure the username and password are correct.
	•	If LDAPS is required, use LDAPS:// and the appropriate port (636).

Error: “OutOfMemoryException”
	•	Reduce the chunk size using the -PageSize parameter (e.g., -PageSize 100).
	•	Ensure the server is returning paged results by setting the PageSize in the query.

Error: “Access Denied”
	•	Verify that the user account has sufficient permissions to query the LDAP server.

Contact

For questions or further assistance, feel free to reach out!
0xrodnt at Twitter ;)
mail: rodnt@protonmail.com

