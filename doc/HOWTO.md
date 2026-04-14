<!-- Copyright (c) 2019-2026 Siemens AG

Licensed under the Apache License, Version 2.0

SPDX-License-Identifier: Apache-2.0-->


# Supported platform

Build procedures and execution was tested at a "Ubuntu 24.04.2 LTS" Linux system
running inside a VMWare virtual machine. But other modern Linux systems should also
be sufficient. The host system (and therfore the VM) needs to be connected to
the Siemens Intranet.

# Setup of the build environment

## Required Tools

The following build tools need to be installed:
* cmake (currently at least version 3.14 is required)
* gcc
* make

CMake will take care of the dependency on Mbed TLS;
currently at least version 3.6.4 is supported.

## Getting all the code

###  Setup the local git repository

Go to a writable directory of your choice and execute

```bash
git clone git@code.siemens.com:product-pki/playground/embeddedCMP.git
```

# Compiling the code

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

# Configuration

The hardcoded CMP client configuration can be found in `program/cmpclient_config.h`.
The CMP client was tested with
* a public reachable CA at http://pki.certificate.fi:8700/pkix
  * internet access is required
  * uncomment `#define INSTA`
* the PPKI playground
  * Siemens intranet access is required
  * uncomment `#define PLAYGROUND`
* a test setup of the LigtweightCmpRaComponent
  * the LigtweightCmpRaComponent an a MockCA needs to be started locally
  * uncomment `#define LOCAL_RA_CA`
* a EjbCA running in a docker container, see [Setting up the EjbCA running in a docker container](#setting-up-the-ejbca-running-in-a-docker-container)
  * docker must be installed and started locally (check with `sudo docker run hello-world`)
  * the EjbCA container needs to be started locally
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

* `-i` invokes the imprinting (IR) usecase
* `-c` invokes the bootstrapping (CR) usecase
* `-k` invokes the key update (KUR) usecase

# Setting up the EjbCA running in a docker container

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

The EjbCA needs few minutes to become ready for serving requests.

After test you may shut down the EjbCA by executing

```bash
docker compose down
```

