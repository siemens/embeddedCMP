<!--Copyright (c) 2019 Siemens AG

Licensed under the Apache License, Version 2.0

SPDX-License-Identifier: Apache-2.0-->

# frdmk64f_CMP-Client

The frdmk64f_CMP-Client provides source code, documentation, and other files for a
proof-of-concept CMP client on the NXP FRDM-K64F platform based on the Kinetis SDK (KSDK).

## License

This software is licensed under the Apache License, Version 2.0.

## Disclaimer

Please note that this software and associated documentation files is a prototypic 
implementation and merely serves as proof-of-concept.
It is explicitly not guaranteed that all related functionality and hardening measures 
needed for productive software have been implemented. 
The development procedures and processes for proof-of-concept implementation are 
not sufficient to assure product-grade software quality. Therefore the code, scripts, 
configuration, and documentation of the software are provided ‘as is’
and can only serve as an example or starting point for further development.

## How to use

For instructions how to get the required underlying sources and then build and use the software
please refer to [HOWTO.md](/cmp_doc/HOWTO.md).

## Software architecture

The following picture gives a rough overview of the software components used by the embeded CMP client.
The bulk of the unterlying software is part of the Kinetis SDK or the Git repository of libcoap.

![SW architecture](/cmp_doc/sw_architecture.jpg)

The generic data flow of the certificates is shown in the following figure.

![Certificate flow](/cmp_doc/certificate_flow.jpg)
