# SPDX-License-Identifier: MIT
# Copyright 2026 Andrey Aleksandrov <aladex@gmail.com>

include $(TOPDIR)/rules.mk

PKG_NAME:=protonvpn-wireguard
PKG_VERSION:=0.2.1
PKG_RELEASE:=1
PKG_MAINTAINER:=Andrey Aleksandrov <aladex@gmail.com>
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/protonvpn-wireguard
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=ProtonVPN WireGuard backend
  URL:=https://github.com/Aladex/protonvpn-wg-luci
  PKGARCH:=all
  DEPENDS:= \
	+ca-bundle \
	+curl \
	+kmod-wireguard \
	+openssl-util \
	+rpcd \
	+rpcd-mod-ucode \
	+ucode \
	+ucode-mod-fs \
	+ucode-mod-math \
	+ucode-mod-ubus \
	+ucode-mod-uci \
	+ucode-mod-uloop \
	+wireguard-tools
endef

define Package/protonvpn-wireguard/description
ProtonVPN WireGuard service for OpenWrt: SRP login (relayed from the LuCI
page), WireGuard certificate registration, server-list cache, WireGuard
interface/peer generation, connectivity verification, scheduled server
rotation and runtime status. Usable from the CLI and ubus without LuCI.
Unofficial; not affiliated with or endorsed by Proton AG.
endef

define Package/protonvpn-wireguard/conffiles
/etc/config/protonvpn
endef

# Script-only package: nothing to compile.
define Build/Configure
endef

define Build/Compile
endef

define Package/protonvpn-wireguard/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/protonvpn $(1)/etc/config/protonvpn

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/protonvpn $(1)/etc/init.d/protonvpn

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/90-protonvpn-migrate $(1)/etc/uci-defaults/90-protonvpn-migrate

	$(INSTALL_DIR) $(1)/usr/share/ucode/protonvpn
	$(INSTALL_DATA) ./files/usr/share/ucode/protonvpn/*.uc $(1)/usr/share/ucode/protonvpn/
	$(SED) "s|^const VERSION = .*|const VERSION = '$(PKG_VERSION)-r$(PKG_RELEASE)';|" \
		$(1)/usr/share/ucode/protonvpn/common.uc

	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode
	$(INSTALL_DATA) ./files/usr/share/rpcd/ucode/protonvpn.uc $(1)/usr/share/rpcd/ucode/protonvpn.uc

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/protonvpn-cache-update $(1)/usr/bin/protonvpn-cache-update
	$(INSTALL_BIN) ./files/usr/bin/protonvpn-rotate $(1)/usr/bin/protonvpn-rotate
	$(INSTALL_BIN) ./files/usr/bin/protonvpn-service $(1)/usr/bin/protonvpn-service
endef

$(eval $(call BuildPackage,protonvpn-wireguard))
