---
layout: post
title: Creating POC's For New CVE's
subtitle: CVE-2024-55560
tags: [CVE]
---

## The Race to Develop PoCs
When a new CVE is published, it often sparks a race to develop a Proof of Concept (PoC) exploit. The participants in this race are as varied as their motivations: Advanced Persistent Threats (APTs) craft PoCs for malicious purposes, security vendors create them to showcase their product’s defenses, and hobbyists dive in for the thrill of the challenge.

For many, though, the idea of creating a PoC can feel daunting—whether you’re new to cybersecurity or a seasoned professional. In this blog post, I’ll share my thought process and walk you through how I developed a same-day PoC for a new vulnerability.

## Understanding CVE-2024-55560
### A Closer Look at the CVE
Not all CVEs are created equal. Some represent low-impact vulnerabilities that are relatively simple to exploit—take **Heartbleed**, for instance. This OpenSSL vulnerability was straightforward to replicate, allowing attackers to extract sensitive data from servers with minimal effort.

On the other end of the spectrum are vulnerabilities like **Spectre and Meltdown**, which are far more complex. Exploiting these required deep knowledge of CPU architectures and timing attacks, making them challenging even for seasoned researchers.

One evening, as I browsed through newly published CVEs, **CVE-2024-55560** caught my attention. Its description read: _"MailCleaner before 28d913e has default values of ssh_host_dsa_key, ssh_host_rsa_key, and ssh_host_ed25519_key that persist after installation."_ Intrigued, I began searching for these keys online, hoping to uncover more details. However, my initial searches only led to vendor copy-paste descriptions of the CVE, offering no additional insight or resources. I decided to take a few hours and see how far I could get in recovering these keys.

SSH keys, like the ones mentioned, serve as a form of authentication that eliminates the need for passwords when accessing a server. If an attacker were to obtain these keys, they could essentially walk straight into the server, bypassing any password-based authentication entirely. This would allow them to impersonate the server or client, potentially compromising the system with little effort. In a real-world scenario, such access could lead to unauthorized entry, data theft, or full system takeover, making this a critical security vulnerability.

### What is MailCleaner?
I had never heard of MailCleaner before, so the first logical step was to learn about it. According to their website:

_"MailCleaner is an Open Source spam filter appliance gateway. An effective way to protect all your email mailboxes against spam and viruses, easy to install, insuring perfect data privacy, free and of 'Swiss made' quality."_

MailCleaner is installed as an edge device, filtering out spam and junk emails before they reach the email server. At the time of writing, there are approximately **3,755** of these edge appliances connected to the internet, with **2,292** running a vulnerable version.

## Investigating the Vulnerability
### Finding the Fix
Next, I turned to GitHub, where MailCleaner’s code is hosted. Commit `28d913eaa044b689eb114f72ebe92d48cb4aaca7` addresses the issue by introducing the following check when installing:
```bash
if [[ "$(sha256sum /etc/ssh/ssh_host_rsa_key | cut -d ' ' -f 1)" == "cf9a7e0cffbc7235b288da3ead2b71733945fe6c773e496f85a450781ef4cf33" ]]; then
	GEN=1
	echo "Disabling default RSA key"
	mv /etc/ssh/ssh_host_rsa_key /etc/ssh/.ssh_host_rsa_key.old
	mv /etc/ssh/ssh_host_rsa_key.pub /etc/ssh/.ssh_host_rsa_key.pub.old
fi
```

This script runs `sha256sum` on the private SSH key and compares it against the hash `cf9a7e0cffbc7235b288da3ead2b71733945fe6c773e496f85a450781ef4cf33`. This hash is likely the signature of the default key. While not explicitly stated, this is the only logical explanation for why this commit is labeled as a fix. If the hash matches, the script disables the default key by backing up and renaming the public and private key files.

### Retrieving The Keys
The private keys were not present anywhere in the GitHub repository. I revisited the official MailCleaner website to investigate how one might install the appliance. Conveniently, the site provided a QCOW2 image download. I downloaded the QCOW2 file, set up a VM on my Proxmox server, and spun up the appliance.

Using the default username and password for the appliance, I successfully logged in and was presented with the following screen:
![pocs](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/creatingpocs/1.png)

`ctrl-c` to drop out of the util:
![pocs](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/creatingpocs/2.png)

Referring back to the GitHub commit, the script checks the private key’s SHA256 hash and, if it matches, moves the key to `/etc/ssh/.ssh_host_dsa_key.old`. As expected, the `/etc/ssh` directory contained several old SSH keys:
![pocs](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/creatingpocs/3.png)

Running `sha256sum` on these keys revealed that their hash matched the one from GitHub. This confirmed that these were the default keys.
![pocs](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/creatingpocs/4.png)

With this confirmation, the default key could be extracted from the VM and used against vulnerable versions of the appliance. You could build a script to exploit this and submit it to ExploitDB or write a Metasploit module.

## Keep It Simple
In the end, this whole process shows that anyone—whether you're a seasoned pro or just starting out—can dive into research, apply critical thinking, and uncover vulnerabilities to create PoCs. It’s about breaking things down, being persistent, and thinking through the problem, even when the concepts seem tricky. Don’t get discouraged if things don’t work right away—persistence and practice make all the difference. With a bit of curiosity and hands-on experience, you’ll find that it gets easier with time. Remember, you don’t need to be an expert to start making an impact in cybersecurity. With the right mindset and a willingness to learn, anyone can contribute meaningfully to the field.
