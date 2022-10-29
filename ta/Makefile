#
# Copyright (c) 2022 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#
define strip-trailing-slashes-and-dots
$(eval _o := $(patsubst %/,%,$(patsubst %/.,%,$(1))))$(if \
$(filter-out $(1),$(_o)),$(call strip-trailing-slashes-and-dots,$(_o)),$(_o))
endef
PYTHON3 ?= python3

BINARY=8aaaf200-2450-11e4-abe2-0002a5d53830

CFG_TEE_TA_LOG_LEVEL ?= 4

# out-dir := $(call strip-trailing-slashes-and-dots,$(O))
# ifeq ($(out-dir),)
# $(error invalid output directory (O=$(O)))
# endif

LDADD += -L/home/miyazawa/prog/optee-qemu/out-br/build/optee_examples_ext-1.0/teep_armadillo_trial/ta/qcbor -lqcbor
# LDADD += -L./qcbor -lqcbor

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
	@echo 'Note: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif

.PHONY: all ta clean

all: ta
	mkdir -p ${TARGET_DIR}/lib/optee_armtz
	cp /home/miyazawa/prog/optee-qemu/out-br/build/optee_examples_ext-1.0/teep_armadillo_trial/ta/qcbor/*.ta ${TARGET_DIR}/lib/optee_armtz
ta:
	@echo "JFOIER(*U#R#IORJ#PRU*#P(R*UJEIWEU"
	@echo $(LDFLAGS)
	@echo "JFOIER(*U#R#IORJ#PRU*#P(R*UJEIWEU"
	$(MAKE) -C qcbor

install:
#	$(echo) '  INSTALL ${DESTDIR}/lib/optee_armtz'
#
# 	$(echo) '  INSTALL ${DESTDIR}/lib/optee_armtz'
# 	$(q)mkdir -p ${DESTDIR}/lib/optee_armtz
# 	$(q)find $(out-dir) -name \*.ta -exec cp {} ${DESTDIR}/lib/optee_armtz \;
# 	$(echo) '  INSTALL ${DESTDIR}/bin'
# 	$(q)mkdir -p ${DESTDIR}/bin
# 	$(q)cp $(out-dir)/xtest/xtest ${DESTDIR}/bin
# 	$(echo) '  INSTALL ${DESTDIR}/$(CFG_TEE_PLUGIN_LOAD_PATH)'
# 	$(q)mkdir -p ${DESTDIR}/$(CFG_TEE_PLUGIN_LOAD_PATH)
# 	$(q)cp $(out-dir)/supp_plugin/*.plugin ${DESTDIR}/$(CFG_TEE_PLUGIN_LOAD_PATH)
