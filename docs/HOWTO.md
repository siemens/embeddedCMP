<!--Copyright (c) 2019 Siemens AG

Licensed under the Apache License, Version 2.0

SPDX-License-Identifier: Apache-2.0-->


# Supported platform

Build procedures and execution was tested at a "Ubuntu 24.04.2 LTS" Linux system
running inside a VMWare virtual machine. But other modern Linux systems should also
be sufficient. The host system (and therfore the VM) needs to be connected to
the Siemens Intranet.

# Setup of the build environment

## Required Tools

The following tools need to be installed:
* cmake
* gcc
* make

## Getting all the code

###  Setup the local git repository

Go to a writeable directory of your choice and execute

```bash
git clone git@code.siemens.com:product-pki/ct_rda/embeddedCMP.git
cd embeddedCMP/external
git clone --recurse-submodules https://github.com/Mbed-TLS/mbedtls.git
cd ..
```

# Compiling the code

Create a build directory and compile the code by executing the commands below

```bash
mkdir -p build
cd build
cmake ..
make
cd ..
```

# Configuration

The hardcoded CMP client configuration can be found in `program/cmpclient_config.h`.
After changing the configuration a recompilation by invoking `make` is required. 


# Running the CMP client

Create the directories for storing the enrollment results and invoke the client.
The enrollment result paths must fit the configuration given in `program/cmpclient_config.h`.

```bash
mkdir -p resources/sdcard_root/SDHC/certs/playground/operat \
		  resources/sdcard_root/SDHC/certs/playground/vendor
./build/embedded_cmp -ick
``` 

# Command line options

The `./build/embedded_cmp` executable supports the options below:

* `-i` invokes the imprinting (IR) usecase
* `-c` invokes the bootstrapping (CR) usecase
* `-k` invokes the key update (KUR) usecase



