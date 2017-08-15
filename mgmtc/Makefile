include $(TOPDIR)/rules.mk

PKG_NAME:=mgmtc
PKG_VERSION:=1.0
PKG_RELEASE:=0

include $(INCLUDE_DIR)/package.mk
 
define Package/$(PKG_NAME)
    SECTION:=net
    CATEGORY:=Network
    DEPENDS:=+libubox +libpthread
    TITLE:=device client to direct broadcast server
endef

define Package/$(PKG_NAME)/description
   this is a cloud client to manage the direct broadcast
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mgmtc  $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/mgmtc.init $(1)/etc/init.d/mgmtc
endef
 
$(eval $(call BuildPackage,$(PKG_NAME)))
