# Registry Persistence Detection
In the intricate realm of cybersecurity, once a piece of malware successfully infiltrates a system, its primary objective is to establish persistence—creating multiple pathways to ensure its unwelcome presence endures. The journey undertaken to breach the target machine fuels the malware's determination to firmly entrench itself. Various techniques are employed to achieve this, ranging from manipulating registry run keys, startup folders, and scheduled tasks to exploiting boot execute keys and browser helper objects.

A common thread in many of these strategies is the manipulation of the Windows Registry, a vital database housing operating system and program settings. Unraveling the intricacies of this database becomes essential to understanding how malware establishes persistence on a compromised system.
## Exploitation
Registry Run Keys stand out as one of the most common types of registry persistence, persisting through reboots.

For users, two common ones include:

- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    - This location stores entries specifying programs or scripts that should run automatically when the current user logs into their Windows account.
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
    - Entries under the `RunOnce` key are designed to run only once during the next user logon.

Administrator privilege ones include:

- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    - This location stores entries specifying programs or scripts that should run automatically when **any** user logs into their Windows account.
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
    - Entries will run once during the next system boot, and then the registry entry will be automatically deleted.
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
    - Usually associated with group policy and system startup.

As an example of exploiting the first registry key, consider this PowerShell script that creates a new registry entry configuring `C:\temp\reg.exe` to run every time the user logs in:
```powershell
$RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$Name         = 'Zonifer'
$Value        = 'C:\temp\reg.exe'
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType String -Force
```

I copied the script onto my Windows 11 lab desktop machine and executed it. The script wrote a new entry to execute `C:\temp\reg.exe` upon every logon.
![IMG](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registypersistencedetection/2.png)

To test this, I logged out, and upon logging back in, I could see a new session on my C2 listener.
![IMG](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registypersistencedetection/3.png)

Log back in and then check the C2
![IMG](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registypersistencedetection/4.png)


This example was broken down quite a bit, but it can all be wrapped into a single malicious binary. When you download and execute some piece of malware, it could create a new file and place it somewhere sneaky on the file system, then write a new registry entry to execute upon logon. If you were to delete the beachhead malware, you would still be infected.

Creating persistence in this manner isn't overly complex, and is very effective. Many threat actors (TAs) engage in this approach, as evidenced by the comprehensive mapping provided by MITRE at [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/). However, from a forensics side, the thought of manually delving into the myriad registry entries can be akin to searching for a needle in a haystack. The sheer volume of entries introduces a daunting task, with numerous possibilities for malicious entries to elude detection. 
## Detection
Apart from the generic advice of keeping Defender up to date and looking at windows event logs, an effective tool for examining registry entries is [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns), a Sysinternals tool. It provides both a PowerShell module and a user-friendly GUI, offering flexibility in usage.
![IMG](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registypersistencedetection/1.png)

The GUI is user-friendly, allowing users to explore various categories of registry entries. In the context of a Logon entry, you can navigate to that tab and identify any malicious registry entries, as showcased in the image below.
![IMG](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registypersistencedetection/5.png)

Autoruns also includes the functionality of filters, allowing users to exclude benign Windows entries. This feature plays a crucial role in elevating the efficiency of the forensics detection process, enabling investigators to hone in on potentially malicious entries with greater precision.

Another notable capability of Autoruns is its support for baselines. When a machine is imaged or confirmed to be in a known good state, Autoruns can capture a baseline of the registry. In the event of a suspected infection or actual compromise, a subsequent baseline can be taken and compared to the original. This baseline comparison serves as a valuable tool for detecting and analyzing changes in the registry, aiding in the identification of potentially malicious alterations.
