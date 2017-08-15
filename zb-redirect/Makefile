#
# Copyright (C) 2008-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=zb_redirect
PKG_RELEASE:=2

include $(INCLUDE_DIR)/package.mk

define KernelPackage/zb_redirect
  SUBMENU:=Other modules
  TITLE:=zhibo service discoery
  FILES:=$(PKG_BUILD_DIR)/zb_redirect.ko
  KCONFIG:=  
endef

define KernelPackage/zb_redirect/description
zhibo request redirect
endef

MAKE_OPTS:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	SUBDIRS="$(PKG_BUILD_DIR)"

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		modules
endef

$(eval $(call KernelPackage,zb_redirect))
