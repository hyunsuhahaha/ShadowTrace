import shutil
import subprocess
from fastapi import APIRouter
from .vpn import vpn_status

router = APIRouter()

TOOLS={"nmap":"sudo apt install nmap","curl":"sudo apt install curl","wget":"sudo apt install wget",
"whatweb":"sudo apt install whatweb","gobuster":"sudo apt install gobuster","feroxbuster":"sudo apt install feroxbuster",
"nikto":"sudo apt install nikto","smbclient":"sudo apt install smbclient","enum4linux-ng":"sudo apt install enum4linux-ng",
"netexec":"sudo apt install netexec","rpcclient":"sudo apt install smbclient","dig":"sudo apt install dnsutils",
"snmpwalk":"sudo apt install snmp","showmount":"sudo apt install nfs-common","ftp":"sudo apt install ftp",
"ssh":"sudo apt install openssh-client","searchsploit":"sudo apt install exploitdb",
"hydra":"sudo apt install hydra","smbget":"sudo apt install smbclient",
"impacket-psexec":"sudo apt install python3-impacket","impacket-mssqlclient":"sudo apt install python3-impacket",
"impacket-GetNPUsers":"sudo apt install python3-impacket",
"impacket-secretsdump":"sudo apt install python3-impacket",
"impacket-lookupsid":"sudo apt install python3-impacket",
"evil-winrm":"sudo apt install evil-winrm","xfreerdp":"sudo apt install freerdp2-x11",
"hashcat":"sudo apt install hashcat","bloodhound-python":"sudo apt install bloodhound.py",
"ike-scan":"sudo apt install ike-scan",
"kerbrute":"apt에 없음 — https://github.com/ropnop/kerbrute/releases 에서 "
           "kerbrute_linux_amd64를 받아 PATH에 kerbrute로 저장"}
@router.get("/api/system/status")
def status():
    tools=[{"name":k,"installed":bool(p:=shutil.which(k)),"path":p,"install":v} for k,v in TOOLS.items()]
    def cmd(*args):
        try:return subprocess.run(args,capture_output=True,text=True,timeout=2).stdout
        except Exception:return ""
    return {"tools":tools,"vpn":vpn_status()}
