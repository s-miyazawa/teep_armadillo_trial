#
# Copyright (c) 2022 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

global-incdirs-y += include
global-incdirs-y += qcbor/inc

srcs-y += teep_armadillo_trial_ta.c

# libdirs += $(ta-dev-kit-dir$(sm))/lib
# libnames += utils
# libdeps += $(ta-dev-kit-dir$(sm))/lib/libutils.a

# To remove a certain compiler flag, add a line like this
#cflags-template_ta.c-y += -Wno-strict-prototypes

libdirs += /home/miyazawa/prog/optee-qemu/out-br/build/optee_examples_ext-1.0/teep_armadillo_trial/ta/qcbor/out

libnames += qcbor
