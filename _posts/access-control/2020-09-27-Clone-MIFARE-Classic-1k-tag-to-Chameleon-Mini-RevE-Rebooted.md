# How to clone a MIFARE Classic 1K tag to Chameleon Mini RevE Rebooted


The official github repository for the [Chameleon Mini RevE Rebooted](https://github.com/iceman1001/ChameleonMini-rebooted). Other revisions of the hardware use different github projects. The RevE Rebooted looks like the image below:

<p align="center">
  <img width="50%" src="/assets/images/access-control/chameleon-mini-revE.png" />
</p>

Tools used:

- [MIFARE Classic Tool (MCT)](https://github.com/ikarus23/MifareClassicTool)
- [TeraTerm](https://ttssh2.osdn.jp/index.html.en)


### Step 1: Dump tag using MIFARE Classic Tool.

<p align="left">
  <img width="30%" src="/assets/images/access-control/mct.jpg" />
</p>

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

	<p align="left">
	  <img width="80%" src="/assets/images/access-control/teraterm-xmodem-send.png" />
	</p>
