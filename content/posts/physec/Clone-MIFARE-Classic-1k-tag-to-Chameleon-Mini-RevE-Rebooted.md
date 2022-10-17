---
title: "Clone Mifare Classic 1k Tag To Chameleon Mini RevE Rebooted"
date: 2020-09-27
description: "How to clone Mifare Classic 1k tags onto the Chameleon Mini RevE Rebooted"
summary: "How to clone Mifare Classic 1k tags onto the Chameleon Mini RevE Rebooted"
tags: ["physical-security","access control"]
---

## How to clone a MIFARE Classic 1K tag to Chameleon Mini RevE Rebooted

The official github repository for the [Chameleon Mini RevE Rebooted](https://github.com/iceman1001/ChameleonMini-rebooted). Other revisions of the hardware use different github projects. The RevE Rebooted looks like the image below:


<img width="50%" src="/images/access-control/chameleon-mini-revE.png" />

Tools used:

- [MIFARE Classic Tool (MCT)](https://github.com/ikarus23/MifareClassicTool)
- [TeraTerm](https://ttssh2.osdn.jp/index.html.en)


### Step 1: Dump tag using MIFARE Classic Tool.

<img width="30%" src="/images/access-control/mct.jpg" />

### Step 2: Convert dump from `.mct` format to `.mfd`

Using bash:

`grep -v '+Sector: ' dump.mct | xxd -r -p > dump.mfd`

Or Python using [this script](https://github.com/dunderhay/mct-to-mfd):

`python3 mct-to-mfd.py dump.mct dump.mfd`


### Step 3: Upload `dump.mfd` to Chameleon Mini RevE Rebooted

- Plug the Chameleon Mini RevE Rebooted in and connect to the device via teraterm.
- Pick an open card slot with `SETTING=X` command and the slot you want to use (`X`: 0 to 7).
- Check the config mode. For example MIFARE Classic 1k:  `CONFIG=MF_CLASSIC_1K`.
- Initiate the file upload using the `UPLOAD` command and selecting the `dump.mfd` file:

	<img width="80%" src="/images/access-control/teraterm-xmodem-send.png" />
