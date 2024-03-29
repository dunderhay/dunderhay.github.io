---
title: "Exploiting vulnserver: Intro"
date: 2019-01-29
description: "I am currently doing OSCE / CTP exam preparation exploiting vulnserver.exe"
summary: "I am currently doing OSCE / CTP exam preparation exploiting vulnserver.exe"
tags: ["vulnserver", "buffer overflow", "exploit dev"]
---

## Background

VulnServer is created by [Stephen Bradshaw](http://www.thegreycorner.com/search/label/vulnserver), as per the GitHub ReadMe:

> Vulnserver is a multithreaded Windows based TCP server that listens for client connections on port 9999 (by default) and allows the user to run a number of different commands that are vulnerable to various types of exploitable buffer overflows.
>
> This software is intended mainly as a tool for learning how to find and exploit buffer overflow bugs, and each of the bugs it contains is subtly different from the others, requiring a slightly different approach to be taken when writing the exploit.

Each command will crash the vulnserver application in different ways in order to teach us something new. If you require help, read the Getting Started section first before diving into each exploit.

*Note: This blog will __not__ cover fuzzing the application. There are some existing blog posts which cover this topic already*


## Getting Started

You will need a Windows 7 host to run the vulnserver application:

- ModernIE (Windows 7) : https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/
- vulnserver : https://github.com/stephenbradshaw/vulnserver

The instructions for running the vulnserver application as per the developer GitHub page:

> To run the software, simply execute vulnserver.exe. The provided essfunc.dll library must be in a location where it can be found by vulnserver.exe - keeping both files in the same directory will usually work fine.
>
> To start the server listening on the default port of 9999, simply run the executable, to use an alternate port, provide the port number as a command line parameter.

Once the application has started, it starts waiting for client connections:

![running-vulnserver](/images/vulnserver/intro/running-vulnserver.png)

Connect to vulnserver on port 9999 using netcat:

```bash
nc -v localhost 9999
```

![nc-vulnserver](/images/vulnserver/intro/netcat-connect-vulnserver.png)

## Commands

You can now type commands, similarly to how you would interact with an FTP server. Issue the `HELP` command (case sensitive) to see what functions are supported by the application:

<img width="60%" src="/images/vulnserver/intro/vulnserver-help-command.png" alt="vulnserver-commands" />

Looking back at the Windows victim machine, the vulnserver application has received a connection from our attacker machine:

![vulnserver-new-connection](/images/vulnserver/intro/vulnserver-new-connection.png)

It is possible to write a python script using sockets and the socket API to send different commands via TCP packets to the vulnserver application. For example, the following script will allow us to programmatically interact with vulnserver running on the victim machine:

```python
#!/usr/bin/env python

import socket
import sys

buffer = 'test'
command = 'TRUN .'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
print '[*] Server response: ' + s.recv(1024)
s.close()
```

As we can see, the `TRUN` command ran successfully:

![python-socket-send-data](/images/vulnserver/intro/python-socket-send-data.png)