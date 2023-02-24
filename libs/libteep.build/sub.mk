#
# Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#
global-incdirs-y += ../libteep/inc

srcs-y += ../libteep/src/teep_common.c
srcs-y += ../libteep/src/teep_cose.c
srcs-y += ../libteep/src/teep_message_decode.c
srcs-y += ../libteep/src/teep_message_encode.c

cflags-lib-y += -DLIBTEEP_OPTEE_CRYPTO_C

cflags-../libteep/src/teep_message_encode.c-y += -Wno-missing-prototypes
cflags-../libteep/src/teep_message_encode.c-y += -Wno-missing-declarations

cflags-../libteep/src/teep_message_decode.c-y += -Wno-missing-prototypes
cflags-../libteep/src/teep_message_decode.c-y += -Wno-missing-declarations
cflags-../libteep/src/teep_message_decode.c-y += -Wno-switch-default
cflags-../libteep/src/teep_message_decode.c-y += -Wno-shadow
cflags-../libteep/src/teep_message_decode.c-y += -Wno-type-limits

# ---- QCBOR location ----
global-incdirs-y += ../QCBOR/inc
libdirs += ../QCBOR.ta
libdeps += ../QCBOR.ta/libqcbor.a
libnames += qcbor

# ---- t_cose location ----
global-incdirs-y += ../t_cose/inc
libdirs += ../t_cose.ta
libdeps += ../t_cose.ta/libt_cose.a
libnames += t_cose
