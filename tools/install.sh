#!/bin/sh
#
# Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#
mkdir -p bin
cp teep_agent_ta/e55897fb-0aad-43ae-83a9-330224acbd1d.ta /lib/optee_armtz/
cp teep_broker/teep_broker bin
