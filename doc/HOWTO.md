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

There is an extra parameter `EMDEDDEDCMP_WRITE_FILES`.
When set with `-DEMDEDDEDCMP_WRITE_FILES=ON`
CMP requests and response messages will be stored as files.
The files will be in DER (Distinguished Encoding Rules) format
and will be written into the embeddedCMP base directory
as `last_request.der`, `last_response.der`,
`last_ir_request.der`, and `last_pki_conf_response.der`.

Switching to Debug mode automatically turns the `EMDEDDEDCMP_WRITE_FILES` parameter on.


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
./build/embedded_cmp -icpk
```
or when built in the source directory:
```bash
./embedded_cmp -icpk
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
* `-p` invokes the bootstrapping (P10CR) use case
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
LocalWords:  DEMBEDDEDCMP LigtweightCmpRaComponent icpk cmp KUR
LocalWords:  xvzf ejbca
 -->
# Add hard-coded X.509 extensions of (ASN.1 type `Extensions`) to the CRMF template

The Java code below gives an example how to write ASN.1 DER-encoded extensions to a file:

```java

import static org.junit.Assert.*;

import java.io.FileOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.Test;


public class BuildAndWriteExtensions {

	static public void main(String[] args) throws IOException {
		ExtensionsGenerator eg=new ExtensionsGenerator();
		eg.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
		eg.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.cRLSign|KeyUsage.keyCertSign));
		// other extensions are possible too, see below
		// eg.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth }));
		// eg.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
		eg.generate().encodeTo(new FileOutputStream(args[0]));
	}


	@Test
	public void testBuilder() throws IOException {
		main(new String[] {"./extensions.der"});
	}
}

```

the `xxd` command allows to convert the binary file to an C array:

```bash
xxd -i --n crmf_extensions ./extensions.der > extension_declaration.h
```

Merge the content of `extension_declaration.h` into `program/cmpclient_config.h`

Recompile the code.

# Use of external provided public keys in CRMF template

If the private subject key is not available no signature based proof of possesion (POPO)
can be used for the CRMF template in the certificate request. So a RAVerified POPO must be
configured and used. This can be done by setting the POPO_METHOD to CMP_CTX_POPO_RAVERIFIED
in `program/cmpclient_config.h`. As result of this the public key is loaded from `PATH_TO_xxxxx_KEY_PEM` instead of internal generation of a fresh keypair for the enrollment.

