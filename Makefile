# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2021 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=mosdns
PKG_VERSION:=5.3.3
PKG_RELEASE:=6

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILE:=LICENSE
PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0
PKG_BUILD_FLAGS:=no-mips16

#GO_PKG:与go.mod一致
GO_PKG:=github.com/IrineSistiana/mosdns/v5
GO_PKG_LDFLAGS_X:=main.version=v$(PKG_VERSION)-$(PKG_RELEASE)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/mosdns
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=IP Addresses and Names
  TITLE:=A plug-in DNS forwarder/splitter
  URL:=https://github.com/IrineSistiana/mosdns
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
endef

define Package/mosdns/description
  MosDNS is a pluggable DNS forwarder/splitter for OpenWrt.
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./* $(PKG_BUILD_DIR)/
endef

#define Build/Compile
#	$(call GoPackage/Build/Compile)
#endef

define Package/mosdns/install
	$(call GoPackage/Package/Install/Bin,$(1))
#	$(INSTALL_DIR) $(1)/etc/mosdns
#	$(INSTALL_DATA) ./files/config.yaml $(1)/etc/mosdns/config.yaml
endef

$(eval $(call GoBinPackage,mosdns))
$(eval $(call BuildPackage,mosdns))
