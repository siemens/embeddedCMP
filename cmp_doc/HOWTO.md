<!--Copyright (c) 2019 Siemens AG

Licensed under the Apache License, Version 2.0

SPDX-License-Identifier: Apache-2.0-->


# Supported hardware

- The code has been developed for the FRDM-K64F board from NXP (see https://www.nxp.com/search?keyword=FRDM-K64F)
- WARNING: board firmware update using a Windows 10 host may corrupt the boot loader or firmware! Make sure to carefuly follow the instructions at
  https://www.nxp.com/support/developer-resources/run-time-software/kinetis-developer-resources/ides-for-kinetis-mcus/opensda-serial-and-debug-adapter:OPENSDA#FRDM-K64F
- Make sure the board uses the latest DAPLink bootloader and DAPLink interface firmware. These can be updated as described at
  https://os.mbed.com/blog/entry/DAPLink-bootloader-update/


# SDK installation

- Register at [www.nxp.com](http://www.nxp.com/) and create an account. 
- Download the [Kinetis SDK for the FRDM-K64F](https://www.nxp.com/support/developer-resources/software-development-tools/mcuxpresso-software-and-tools/mcuxpresso-software-development-kit-sdk:MCUXpresso-SDK) (tested with version 2.6).
- After clicking the "Download" button, choose "Select Development Board" from the page popping up. Here you can search for the "frdm-k64f" board. Click on the suggested board and perform "Build MCUXpresso SDK" step on the right side.
- Add all desired middleware by clicking on "Add software component" (for the CMP_Client: CMSIS DSP Libary, FatFS, lwIP, mbedtls, MMCAU, sdmmc stack, USB stack) and download the SDK.
- Download the [MCUXpresso IDE](https://www.nxp.com/support/developer-resources/software-development-tools/mcuxpresso-software-and-tools/mcuxpresso-integrated-development-environment-ide:MCUXpresso-IDE) 
- Choose the appropriate IDE version which is determined by the SDK version (see "System Requirements").
- After installation of the IDE, open MCUXpresso and drag and drop the SDK zip file into the "Installed SDKs" view of MCUXpresso IDE.
	
Note that the Download Manager (NetSession Interface) is not needed -
its use can be declined on the bottom of the page, then click OK.


# Getting all the code

## Setup of SDK components

- To create the same folder structure as expected from our include files, please also follow the guidelines given further below.
- Create a "New project..." from inside the Quickstart Panel and choose the frdmk64f board.
- Select "UART" from the "Project Options" and "MK64FN1M0VLL12" from the "Device Packages".
- Switch to the "Drivers" tab and check if all the following drivers are selected (clock, common, enet, flash, gpio, port, rnga, sdhc, sim, smc, sysmpu, uart). Do not uncheck pre-selected drivers!
- Switch to the "Utilities" tab and check if all the following utilities are selected (assert, debug_console, serial_manager, serial_manager_uart, uart_adapter).
- Switch to the "Middleware" tab and check if all the follwoing modules are selected (File System, Memories, Network, Security).
- You may change the project name and then click the "Finish" button.

## Setup of libcoap components

- Download the [libcoap](https://github.com/obgm/libcoap/tree/master) and copy the unziped "libcoap-master" folder in the top working directory of your MCUXpresso project (The provided example is tested with version 4.1.2, please use this version!).
- Change to the unpacked "libcoap-master" directory and copy the file "coap_config.h.lwip". Rename it to "coap_config.h" and save it in the same directory.
- Switch to the following directory: "libcoap-master/include/coap" and edit the file ending of "coap.h.in" to "coap.h".

## Setup of CMP client components
- Download the "frdmk64f_CMP-Client" project and copy the folders "cmpclient", "cmplib" and "resource" as well as the file "frdmk64f_CMP-Client.mex" in the top directory of your project.

## Setup of mbed-os components

- Download the [mbed-os](https://github.com/ARMmbed/mbed-os) and unzip the folder. Change to the following directory: "mbed-os/targets/TARGET_NXP/TARGET_MCUXpresso_MCUS/TARGET_MIMXRT1050/TARGET_EVK/" and copy the two files "fsl_phy.c" and "fsl_phy.h". Paste these two files in the directory "board/" of your project and overwrite the existing files in there.

## Setup of lwip_httpd_mbedtls components

- From inside the Quickstart panel of your IDE select "Import SDK example(s)...", choses the frdmk64f board and click "Next". Choose in the "lwip_examples" tree the example named "lwip_httpssrv_mbedTLS_bm", switch the SDK debug console to UART and click the Finish button. These guarantee that the folder structure is correct.
- Switch to the newly created project folder. Copy and paste the folder "lwip_httpd_mbedtls" inside your workspace directory of the CMP-Client project.
- Change to "lwip/port/" folder, copy the four files "enet_ethernetif.c", ""enet_ethernetif.h", "enet_ethernetif_kinetis.c" and "enet_ethernetif_priv.h" and paste them in the same named folder in the CMP-Client project directory.
- Change to "lwip/src/" of your example project, copy the folder "apps" and paste them to the same location of your CMP-Client project. Change to "lwip/src/apps" and rename the folder in this directory to "httpd".
- Change to "lwip/src/include/lwip/" of your example project and copy the "apps" folder to your CMP-Client project.
- After this step you do not longer need this lwip example. You can delet this from your project Explorer.

## Edit the folder structure of your project

- After these steps the folder structure is not exactly how we expect. Therefore you have to adapt some folders and/or files.
- Change to "fatfs/" folder, cut the file "ffconf.h" and paste it to the subfolder "fatfs_include/".
- In the case that a folder named "usb/" is created, delet the whole directory.
- Change to "lwip/src/include/compat/" and cut the folder "posix". Change to the directory "lwip/src/include/" and paste this folder in there.
- Change to "source/" folder and delete the initial created main source file. It should be named like "<project_name>.c"

## General configurations

- Open the project properties and switch to the tab "C/C++ General" -> "Paths and Symbols" -> "Source Location". The following paths have to be included there by clicking the "Add folder..." button: 
	* /cmpclient
	* /cmplib
	* /fatfs/fatfs_source
	* /libcoap-master/src
	* /lwip/port
	* /lwip/src
	* /lwip_httpd_mbedtls
	* /sdmmc/port
	* /sdmmc/src

After this just click "Apply".
- Switch to the "Symbols" tab and add a new symbol with name MBEDTLS_CONFIG_FILE and the value '"ksdk_mbedtls_config.h"'. (all the quotes are needed!)
- Switch to the "Includes" tab. Several paths have to be included. Double check for every path, that all folders pop up in all three languages (namely Additional Assembly Source File, Assembly and GNU C). Therefore press "Add..." button to add missing directories. In the end the include directories have to show up in the same order as the list below. If this is not the case, there might be conflicts with references to some include files:
	* drivers
	* component/uart
	* utilities
	* component/serial_manager
	* board
	* lwip/src/include/lwip/apps
	* lwip/port/arch
	* libcoap-master/include/coap
	* lwip/src/include/lwip
	* lwip/src/include/lwip/priv
	* lwip/src/include/lwip/prot
	* lwip/src/include/netif
	* lwip/src/include/netif/ppp
	* lwip/src/include/netif/ppp/polarssl
	* lwip/src/include/posix
	* lwip/src/include/posix/sys
	* device
	* CMSIS
	* component/lists
	* lwip/src/include
	* fatfs/fatfs_include
	* libcoap-master
	* libcoap-master/include
	* sdmmc/inc
	* cmplib
	* mmcau/mmcau_include
	* mbedtls/include/mbedtls
	* mbedtls/port/ksdk
	* mbedtls/include
	* cmpclient
	* lwip/port
	* lwip_httpd_mbedtls
	* source
	* lwip/src
In the end you can remove unnecessary includes and click "Apply and Close".
- To avoid unnecessary code, some files inside your project can be excluded from build. Therfore right click on the following files and select "Resource Configuration --> Exclude from Build": 
	* lwip/src/apps/httpd/fsdata.c
	* lwip/src/apps/httpd/fs/makefsdata/makefsdata.c
	* libcoap-master/src/coap_io.c

## Setup of pin and memory configuration

- Open the MCUXpresso Config Tools via the tab "ConfigTools" -> "Pins" on the top of your MCUXpresso window. 
- After launching the Config Tool, select tab "ConfigTools" again and switch to "Import Configuration (*.mex)" and browse the .mex file named "frdmk64f_CMP-Client.mex" as well as the current Target project. At least press the "Finish" button.
- Now press the "Update Code" button in the top toolbar of the Config Tool. When all steps are performed correct, the window will switch back to your project view.
- Open the project properties and switch to "C/C++ Build --> Settings". Select from the "Tool Settings" tab under"MCU Linker" the "Managed Linker Script" point. On the right side of the window you should see the region, location and size of the heap and the stack. Edit the size of the heap to "0x14800", the size of the stack to "0x1000" and click "Apply and Close".

## Import patches

- The last step before you should be able to build the prject is to apply the patches which were delivered by the file "config_and_debug_tweaks.diff". Therefore change to the top directory of your project and apply the following command `patch -p1 -l <config_and_debug_tweaks.diff`. 
- Note: You may get the error message "Failed at ... (different line endings).". If this is the case you have to switch the line endings either in the patch file or in the files in your project. If you like to change the line endings in your project, select the appropriate file in your project explorer and click on "File --> Convert Line Delimiters To --> Unix. After apllying this to all patched files, the above command will work appropriate.


# CMP client setup and configuration

- Make sure that the "SDK Debug console" is set to "UART console" and that the "library/header type" used by the project is "Redlib(nohost)".
  Both properties can be set using the IDE link "Quick settings" in the lower left corner and should be set in the given order: first "SDK Debug console" and then "library/header type".
- Connect the FRDM-K64F board by USB to your host running the IDE
- Connect the FRDM-K64F board by Ethernet to the host running the CMP server, i.e. an RA or CA
- Optionally change IP address, netmask and gateway address in cmpclient/http_helper.c according to your network setup.
- Optionally change CMP server IP address, port and path in cmpclient/cmpclient_config.h to according to your server setup for IMPRINTING, BOOTSTRAPPING, and UPDATING.
- Copy the directories below [resources/sdcard_root/SDHC](/resources/sdcard_root/SDHC) to a SDCard and insert the card into the FRDM-K64F board. 

## CMP client configuration parameters

To configure the basic behavior of the CMP client adapt the appropriate
`#define`s in the file [cmpclient_config.h](/cmpclient/cmpclient_config.h).
One can choose between a UART terminal based CLI
or a HTTP server control of your CMP client.
Therefore just edit the following line of code:
```c
#define CMP_CLIENT_HTTPD 0 /* define to 1 to enable demo http server, else 0 */
```

Another major configuration is the selection of the CMP server to be used.
For the pre-defined CMP test servers you just need to uncomment the appropriate line, e.g.:
```c
/* select CA to be used */
  #define INSTA
//#define NETGUARD
```

Also the paths where to store the appropriate certificates or keys are set depending
on the CA which should be used. The corresponding macros for these paths are defined
in each section of the respective CA type.

The generic data flow of the certificates
with the corresponding macros is shown in the following figure:

![Certificate flow](/cmp_doc/certificate_flow.jpg)

# Running the CMP client

- select and open a serial terminal (in the NXP MCUxpresso IDE,
use key combination "ctrl-alt-shift-t" to open the terminal selector window;
for the input field with label "Choose terminal:", select "Serial Terminal";
for the input field with label "Serial port:", select, e.g., "COM5").
- All console-based output (such as debug/info/error messages) appears on the UART terminal.
- This PoC supports two major user interaction modes: either via a built-in http server or a very basic 'CLI' on the UART terminal, which uses simple key strokes as input
- Define the C preprocessor symbol "CMP_CLIENT_HTTPD" with value "1" to enable the http server
	  NOTE: especially chain verification operations take time during which - in the current 'bare metal' implementation - the http server is blocked.
		This may lead to timeouts in the browser and undefined behavior of the client due to unprocessed TCP RST packets!
- Make sure that the CMP server is running and can be reached (in particular, access to its port is not blocked by an active firewall)
- Select Debug in the Quickstart Panel in the MCUXpresso IDE
- Wait for Code compilation, download and start until the main entry breakpoint is reached
		(Hint: configure "stop all" for the debug probe) 
- Resume the main thread, wait until "enter main processing loop." is shown in console output.
- For http server control:
	- Use a web browser (chrome is preferred because it does not have tight timeouts) and connect to the https server running on the FRDM-K64F board, go to
		"https://IP_address_of_FRDM-K64F_board/wwwroot/index.htm"
	- Accept TLS server certificate as trusted in browser
	- Select one of the usecases: 
		- Imprinting, Botstrapping, Updating and 
		- HTTP or CoAP as transport
- For UART terminal based 'CLI':
	- Follow the instructions on the terminal
- Watch the Debug console output on the UART terminal for results and diagnostics.
