---
layout: post
title: Installing Havoc C2 On Kali Linux 
subtitle: Guide
thumbnail-img: /assets/img/havoc-kali/Havoc.png
tags: [GUIDE]
---

## Installing Havoc C2 On Kali Linux
Havoc is a open source Command and Control software developed by C5pider. 

### Downloading The Source
The source code for Havoc is hosted on github, run the following command to download it:
```bash
git clone https://github.com/HavocFramework/Havoc.git
```

Then move into the source code's directory:
```bash
cd Havoc
```

### Installing Dependencies
There are quite a few dependencies to download:

```bash
sudo apt install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev python3-dev libboost-all-dev mingw-w64 nasm
```

### Building the Team Server
Havoc operates in a client server model. We'll first build the server portion:
```bash
cd teamserver
go mod download golang.org/x/sys
go mod download github.com/ugorji/go
cd ..
make ts-build
```

The server is now built and we can do some customization. If you want to change the default credentials you'll need to edit the Operator section in: `Havoc/profiles/havoc.yaotl`

There are some other settings in there you can play with but thats out of the scope of this blog post.

To start the team server run:
```bash
./havoc server --profile ./profiles/havoc.yaotl
```

You should see something similar to this:

![visual](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/havoc-kali/1.png)

### Building the Client
With the team server up and running we can now build the client that we will use to connect to it, in the Havoc root run:
```bash
make client-build
./havoc client
```

![Havoc](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/havoc-kali/2.png)


### Connecting to the Team Server
After building the client and running it enter in the host, port (40056), username and password. The default username and password is `Neo:password1234`. If you see the screen below you can now create listeners and payloads!


![Havoc](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/havoc-kali/3.png)

