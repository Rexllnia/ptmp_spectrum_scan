include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk
 
PKG_NAME:=spectrum_scan
PKG_RELEASE:=1.0
 
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)
PKG_CONFIG_DEPENDS :=
 
include $(INCLUDE_DIR)/package.mk
 
define Package/$(PKG_NAME)
	SUBMENU:=Utilities
	CATEGORY:=Ruijie Properties
	TITLE:=spectrum_scan utility
	DEPENDS:=+libuci +libubus +libubox +libdebug +libpthread +libjson-c
endef
 
define Package/$(PKG_NAME)/description
	This is spectrum_scan.
endef
 
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef
 
 
define Build/Configure
endef
 
define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)"\ 
		LDFLAGS="$(TARGET_LDFLAGS)"
endef
 
define Package/$(PKG_NAME)/install	
	$(INSTALL_DIR) $(1)/tmp/spectrum_scan/
	$(INSTALL_DIR) $(1)/etc/spectrum_scan/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/spectrum_scan.init $(1)/etc/init.d/spectrum_scan
	$(INSTALL_DIR) $(1)/usr/local/lua/dev_sta/
	$(INSTALL_BIN) ./files/spectrumScan.lua $(1)/usr/local/lua/dev_sta/spectrumScan.lua
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/spectrum_scan.elf $(1)/usr/sbin/spectrum_scan.elf
endef
 


$(eval $(call BuildPackage,$(PKG_NAME)))
