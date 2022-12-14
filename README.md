# teep_armadillo_trial

`teep_armadillo_trial` is a proof of concept program to test the library for the [IETF TEEP Protocol](https://tools.ietf.org/html/draft-ietf-teep-protocol) at the IETF115 hackathon.
It was run on Qemu at IETF115, but is going to be run on a real device "Armadillo" at IETF116.

## Requirement

* [OP-TEE on QEMU v8](https://optee.readthedocs.io/en/latest/building/devices/qemu.html#qemu-v8)
* [QCBOR](https://github.com/laurencelundblade/QCBOR)
* [t_cose](https://github.com/laurencelundblade/t_cose)
* [libcsuit](https://github.com/yuichitk/libcsuit)
* [libteep](https://github.com/yuichitk/libteep)

## Screen Shot

![Screen Shot](docs/screenshot.jpg "Screen Shot")

## IETF115

![Screen Shot](docs/ietf115result.png "IETF115result")

Essentially, libteep should be executed in TEE.

## Software Stack (Ideal Stack at IETF116)

![Software Stack](docs/softwarestack-ietf116.png "Software Stack")

## License and Copyright

BSD 2-Clause License

Copyright (c) 2022 SECOM CO., LTD. All Rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
