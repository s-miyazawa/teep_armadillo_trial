#
# Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#
global-incdirs-y += ../QCBOR/inc

srcs-y += ../QCBOR/src/UsefulBuf.c
srcs-y += ../QCBOR/src/qcbor_encode.c
srcs-y += ../QCBOR/src/qcbor_decode.c

############################################################
# TEE can't use math.h
cflags-lib-y += -DUSEFULBUF_DISABLE_ALL_FLOAT
cflags-lib-y += -DMATH_DISABLE

# TODO: QCBOR/src/qcbor_encode.c:CheckDecreaseNesting should be static function
cflags-../QCBOR/src/qcbor_encode.c-y += -Wno-missing-prototypes
cflags-../QCBOR/src/qcbor_encode.c-y += -Wno-missing-declarations
