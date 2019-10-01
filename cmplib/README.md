## Synopsis

This client-side library implementation of RFC 4210 “Certificate Management
Protocol (CMP)” utilizes [Arm® Mbed™ TLS](https://tls.mbed.org/) as crypto
library.

It is mainly intended for use on constrained embedded IoT devices, e.g. based
on [Arm Mbed OS](https://os.mbed.com/), but will also work on any other system
supported by the Mbed TLS library. It is commonly tested on the NXP
Semiconductors’ FRDM-K64F development platform utilizing Mbed OS, and on Debian
Linux®.

Having the goal to be lightweight, initial focus is on providing basic support
for Initial Registration (IR/IP), protected by means of MSG\_MAC\_ALG based on
reference and secret values, as well as MSG\_SIG\_ALG based on external identity
certificates (cf. RFC 4210, E.7). Later, other CMP functionality such as those
for Key Update (KUR/KUP) could be added.

## Code Example

See the [reference CMP client](https://github.com/nokia/CMPclient-embedded) for
a complete code example.

    cmp_ctx ctx;

    cmp_ctx_init( &ctx, &ctr_drbg );
    cmp_ctx_init_hardcoded( &ctx, &ctr_drbg );

    cmp_ctx_set_sender_name( &ctx, mysubject );
    cmp_ctx_set_subject_name( &ctx, mysubject );

    cmp_ctx_set_recipient_name( &ctx, cmp_srv_subject );

    cmp_ctx_set_new_key( &ctx, &new_pk_ctx );
    cmp_ctx_set_cl_crt( &ctx, &vendor_crt );
    cmp_ctx_set_cl_crt_chain( &ctx, &vendor_sub_ca_crt );
    cmp_ctx_set_prot_key( &ctx, &vendor_pk_ctx );

    cmpcl_ir(&ctx);

## Motivation

A fully featured CMP client based on OpenSSL exists, but it is not possible to
use it on ARM Mbed devices.  Also developers of other constrained devices might
prefer to select Mbed TLS over OpenSSL.

## Installation

### Download

This library cannot be used standalone, but needs to be used through by an
application such as the
[reference CMP client](https://github.com/nokia/CMPclient-embedded)
also available on GitHub:

If the code is cloned from GitHub, one might prefer to use the --recurse flag
ot immeditaly also clone Mbed TLS which is referenced as a git submodule.

    $ git clone --recursive https://github.com/nokia/CMPclient-embedded-lib.git

### Building

The library can be built using e.g. GCC for Linux, or the Mbed CLI and the GNU
ARM Embedded Toolchain.

#### GCC for Linux

The library (including the Mbed TLS dependency) can be build using make

    $ make

This results in **libcmpcl.a**

#### Mbed CLI and GNU ARM Embedded Toolchain

The GNU ARM Embedded Toolchain is one way to build for Mbed OS.  This however
only makes sense to use it for the high-level application including this
library.

## API Reference

See **cmpcl.h** for the API.

## Tests

Currently there are no tests.

## Beware

This is not yet to be considered as production grade code.

## Contributors

Feel free to contact the main author if you are interested to contribute.

## License

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


The CMP client contains code derived from examples and documentation for
mbedTLS by ARM
Copyright (C) 2006-2017, ARM Limited, All Rights Reserved
SPDX-License-Identifier: Apache-2.0


Arm® and Mbed™ are registered trademarks or trademarks of Arm Limited (or its
subsidiaries) in the US and/or elsewhere.

NXP is a trademark of NXP B.V.

Debian is a registered trademark owned by Software in the Public
Interest, Inc.

Linux® is the registered trademark of Linus Torvalds in the
U.S. and other countries
