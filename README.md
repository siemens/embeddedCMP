<!-- Copyright (c) 2019 Siemens AG

Licensed under the Apache License, Version 2.0

SPDX-License-Identifier: Apache-2.0 -->

# CMP Client

This project provides source code, documentation, and other files for a CMP client
implementation. This prototypical code explicitly does not have production quality
but constructively proves that CMP can be implemented and used
even on a device that does not have the capacity to contain OpenSSL
nor a proper operating system.

It essentially uses just the cryptography support provided by mbedTLS
and some basic I/O functionality including a bare-bones HTTP or CoAP client.
As expected, its code size, network bandwidth, and computation resource
footprint are similar to an EST implementation (while it does not need (d)TLS
but performs self-contained message protection as far as needed).

This also serves as a PoC for current standardization efforts at the IETF
on profiling the CMP standard 
[RFC 4210](https://tools.ietf.org/html/rfc4210),
[RFC9480](https://tools.ietf.org/html/rfc9480),
[RFC9481](https://tools.ietf.org/html/rfc9481) 
[RFC6712](https://tools.ietf.org/html/rfc6712)
towards use in embedded systems and the IoT.

## License

This software is licensed under the Apache License, Version 2.0.

## Disclaimer

Please note that this software and associated documentation files is a prototypical
implementation and merely serves as proof-of-concept.
It is explicitly not guaranteed that all related functionality and hardening measures
needed for productive software have been implemented.
The development procedures and processes for proof-of-concept implementation are
not sufficient to assure product-grade software quality. Therefore the code, scripts,
configuration, and documentation of the software are provided ‘as is’
and can only serve as an example or starting point for further development.

## How to use

For instructions how to get the required underlying sources
and then build and use this software
please refer to [HOWTO.md](/docs/HOWTO.md).

## Software architecture

The following picture gives a rough overview of the software components used by the embedded CMP client.

```plantuml
@startuml
[CMP main] as main
note as mainN
program entry point
file: program/cmp_main.c
endnote
mainN .. main

[CMP client] as client
note as clientN
implements toplevel CR, IR 
and KUR transactions
file: program/cmp_client.c
endnote
clientN .. client

[Credential Storage] as storage
note as storageN
implements credential 
load and store functions
file: program/credential_storage.c
endnote
storageN .. storage

[Mbed-TLS transport] as transport
note as transportN
implements HTTP and TLS 
send and receive support
file: program/mbedtls_transport.c
endnote
transportN .. transport

[Mbed-TLS builtin ASN.1 support] as asn1
note as asn1N
implements low level ASN.1 
encoding and decoding
file: mbedtls/...
endnote
asn1N .. asn1

[CMP ctx] as ctx
note as ctxN
provides and holds all 
CMP states and parameters
related to one CMP transaction
file: library/cmpcl_ctx.c
endnote
ctxN .. ctx 

[CMP library] as lib
note as libN
implements some 
helper functions
file: library/cmpcl_lib.c
endnote
libN .. lib

[CMP write] as write
note as writeN
implements CMP specific 
message encoder functions
file: library/cmpcl_write.c
endnote
writeN .. write

[CMP read] as read
note as readN
implements CMP specific 
message decoder functions
file: library/cmpcl_read.c
endnote
readN .. read

[CMP session mgmt] as ses
note as sesN
implements CMP 
transaction management
file: library/cmpcl_ses.c
endnote
sesN .. ses


main .> transport: creates
main -d--> client: invokes

client .> ctx: creates 
client -l-> storage: uses
client -d--> ses: invokes

ses -> write: uses
ses -> read: uses
ses -d--> transport: invokes

read --> asn1: uses
write --> asn1: uses

transport -l-> storage: uses

@enduml
```
