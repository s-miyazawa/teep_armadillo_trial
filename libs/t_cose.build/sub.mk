#
# Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#
global-incdirs-y += ../t_cose/inc
global-incdirs-y += ../t_cose/src

srcs-y += ../t_cose/src/t_cose_sign1_verify.c
srcs-y += ../t_cose/src/t_cose_sign1_sign.c
srcs-y += ../t_cose/src/t_cose_util.c
srcs-y += ../t_cose/src/t_cose_parameters.c
srcs-y += ../t_cose/src/t_cose_short_circuit.c
srcs-y += t_cose_gpapi_crypto.c

cflags-lib-y += -DT_COSE_USE_OPENSSL_CRYPTO=0
cflags-lib-y += -DT_COSE_USE_PSA_CRYPTO=0
cflags-lib-y += -UT_COSE_USE_PSA_CRYPTO
cflags-lib-y += -DT_COSE_USE_B_CON_SHA256=0
cflags-lib-y += -DCOSE_ALGORITHM_RESERVED=0
cflags-lib-y += -DT_COSE_DISABLE_EDDSA=1
cflags-lib-y += -DT_COSE_USE_OPTEE_GP_CRYPTO=1

# ---- QCBOR location ----
global-incdirs-y += ../QCBOR/inc
libdirs += ../QCBOR.ta/QCBOR
libdeps += ../QCBOR.ta/QCBOR/libqcbor.a
