# TEEP Armadillo Trial

This is a program to demonstrate the TEEP protocol on a real device.
This will be demonstrated at IETF 116.
We will use an Armadillo-IoT Gateway G4 as a real device.

## Directory Structure

````
📁 teep_armadillo_trial
├── 📁 libs
│   ├── 📁 libteep (submodule of libteep)
│   └── 📁 libteep.build (makefiles for building libteep for TA)
│   ├── 📁 QCBOR (submodule of QCBOR)
│   ├── 📁 QCBOR.build (makefiles for building QCBOR for TA)
│   ├── 📁 t_cose (submodule of t_cose)
│   └── 📁 t_cose.build (makefiles for building t_cose for TA)
├── 📁 teep_agent_ta (TEEP Agent: Trusted Application)
└── 📁 teep_broker (TEEP Broker: Normal Application running in REE. The TEEP Broker acts as an intermediary between the TAM and the TEEP Agent.)
````

## Installation

Put the `teep_armadillo_trial` directory and the optee directory in the same directory at the same level as shown below.

````
📁 awesomeproject
├── 📁 teep_armadillo_trial (This Project)
└── 📁 optee   (OP-TEE SDK and QEMU)
````

### optee (OP-TEE SDK and QEMU)

https://optee.readthedocs.io/en/latest/building/devices/qemu.html#qemu-v8

````
$ mkdir -p awesomeproject/optee
$ cd awesomeproject/optee
$ repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml
$ repo sync
$ cd build
$ make toolchains
$ make QEMU_VIRTFS_ENABLE=y QEMU_USERNET_ENABLE=y CFG_CORE_ASLR=n MBEDTLS_ECDSA_DETERMINISTIC=y
````

### `teep_armadillo_trial`

````
$ mkdir -p awesomeproject
$ cd awesomeproject
$ git clone --recurse-submodules git@github.com:s-miyazawa/teep_armadillo_trial.git
$ cd teep_armadillo_trial
$ cd libs
$ patch -u -p1 -d . < libs.patch
$ cd ..
$ make -f Makefile.qemu # or $ make -f Makefile.armadillo
````

## Run the programs

````
$ cd awesomeproject/optee/build
$ sudo apt install build-essential libcap-ng-dev libattr1-dev  # More packages might be needed.
$ make run-only QEMU_VIRTFS_ENABLE=y QEMU_USERNET_ENABLE=y CFG_CORE_ASLR=n MBEDTLS_ECDSA_DETERMINISTIC=y QEMU_VIRTFS_HOST_DIR=$(pwd)/../..
````

When executed, three terminal emulators are launched.
They are a terminal for qemu, a terminal for REE, and a terminal for TEE, respectively.

### QEMU

Run the emulator with the c command.

````
QEMU 7.0.0 monitor - type 'help' for more information
(qemu) c
````

### REE

After logging into REE, mount the filesystem of the qemu host.

````
Welcome to Buildroot, type root or test to login
buildroot login: root
# mount -t 9p -o trans=virtio host /mnt/host
# cd /mnt/host/teep_armadillo_trial/
# ./tools/install.sh && ./bin/teep_broker
````

## License and Copyright

BSD 2-Clause License

Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.

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
