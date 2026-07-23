<!-- Copyright (c) 2019-2026 Siemens AG

Licensed under the Apache License, Version 2.0

SPDX-License-Identifier: Apache-2.0-->


# Supported platform

Build procedures and execution was tested at a "Ubuntu 24.04.2 LTS" Linux system
running inside a VMWare virtual machine. But other modern Linux systems should also
be sufficient. The host system (and therefore the VM) needs to be connected to
the Siemens Intranet.

# Setup of the build environment

## Required Tools

The following build tools need to be installed:
* cmake (currently at least version 3.14 is required)
* gcc
* make

CMake will take care of the dependency on Mbed TLS;
currently at least version 3.6.4 is supported.

## Getting the code

###  Setup the local git repository

Go to a writable directory of your choice and execute

```bash
git clone git@code.siemens.com:product-pki/playground/embeddedCMP.git
```

# Building

Using CMake is recommended.

Optionally create a build directory and compile the code like this:
```bash
mkdir -p build
cd build
cmake .. -B .
make
cd ..
```
Alternatively, you can also build directly in the source directory:
```bash
cmake .
make
```

By default, CMake builds are in Release mode.
This may also be enforced by defining the environment variable `NDEBUG`.
For switching to Debug mode, use `cmake` with `-DCMAKE_BUILD_TYPE=Debug`.
The chosen mode is remembered in `CMakeCache.txt`.
Debug mode implies `-=0 -g3 -fsanitize=address,undefined -fno-sanitize-recover=all`

To switch on verbose logging, use `cmake` with `-DEMBEDDEDCMP_DEBUG=ON`.

# Configuring the client application

The hard-coded CMP client configuration can be found in `program/cmpclient_config.h`.
The CMP client was tested with
* a public reachable CA at http://pki.certificate.fi:8700/pkix
  * Internet access is required
  * uncomment `#define INSTA`
* the PPKI playground
  * Siemens intranet access is required
  * uncomment `#define PLAYGROUND`
* a test setup of the LigtweightCmpRaComponent
  * the LigtweightCmpRaComponent an a Mock CA needs to be started locally
  * uncomment `#define LOCAL_RA_CA`
* a EJBCA running in a docker container, see [Setting up the EJBCA running in a docker container](#setting-up-the-ejbca-running-in-a-docker-container)
  * docker must be installed and started locally (check with `sudo docker run hello-world`)
  * the EJBCA container needs to be started locally
  * uncomment `#define DOCKER_EJBCA`

After changing the configuration in `program/cmpclient_config.h` a recompilation
as described in [Compiling the code](#compiling-the-code) is required.


# Running the CMP client

Create the directories for storing the enrollment results and invoke the client.
The enrollment result paths must fit the configuration given in `program/cmpclient_config.h`.

```bash
./build/embedded_cmp -ick
```
or when built in the source directory:
```bash
./embedded_cmp -ick
```

# Running the CMP client tests

Create the directories for storing the enrollment results and invoke the client.
The enrollment result paths must fit the configuration given in `program/cmpclient_config.h`.

```bash
cd build
make test
cd ..
```
or when built in the source directory:
```bash
make test
```


# Command line options

The `embedded_cmp` executable supports the options below:

* `-i` invokes the imprinting (IR) use case
* `-c` invokes the bootstrapping (CR) use case
* `-k` invokes the key update (KUR) use case

# Setting up the EJBCA running in a docker container

* If not already done install and start a docker engine as described at
https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository.

* Check docker engine setup and start by executing

```bash
docker run hello-world
```

* Go to a writable directory of your choice and execute

```bash
wget https://github.com/siemens/gencmpclient/raw/refs/heads/master/test/recipes/80-test_cmp_http_data/EJBCA/ejbca-docker.tar.gz
tar xvzf ejbca-docker.tar.gz
cd ejbca-docker/
docker compose up -d
```

The EJBCA needs few minutes to become ready for serving requests.

After test you may shut down the EJBCA by executing

```bash
docker compose down
```


<!--
LocalWords:  cmake mkdir cd NDEBUG DCMAKE fsanitize fno sudo CR
LocalWords:  DEMBEDDEDCMP LigtweightCmpRaComponent ick cmp KUR
LocalWords:  xvzf ejbca
 -->
