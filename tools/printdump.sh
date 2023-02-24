#!/bin/sh
#
# Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#
CROSS_COMPILE=$PWD/../optee/toolchains/aarch64/bin/aarch64-linux-
cat dump.txt | python ../optee/optee_os/scripts/symbolize.py -d ./teep_agent_ta
