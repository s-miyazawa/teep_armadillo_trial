#
# Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

#
# Setup for QCBOR
#
global-incdirs-y += ../libs/QCBOR/inc
libdirs += ../libs/QCBOR.build
libdeps += ../libs/QCBOR.build/libqcbor.a
libnames += qcbor

#
# Setup for t_cose
#
global-incdirs-y += ../libs/t_cose/inc
libdirs += ../libs/t_cose.build
libdeps += ../libs/t_cose.build/libt_cose.a
libnames += t_cose

#
# Setup for libteep
#
global-incdirs-y += ../libs/libteep/inc
libdirs += ../libs/libteep.build
libdeps += ../libs/libteep.build/libteep.a
libnames += teep

#
# Setup for teep agent
#
global-incdirs-y += ./include
srcs-y += src/create_evidence.c
srcs-y += src/create_query_response.c
srcs-y += src/keys.c
srcs-y += src/utils.c
srcs-y += src/teep_agent_ta.c
cflags-src/create_query_response.c-y += -Wno-strict-aliasing
cflags-y += -DLIBTEEP_OPTEE_CRYPTO_C
