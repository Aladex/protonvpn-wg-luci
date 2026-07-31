# SPDX-License-Identifier: MIT
# Copyright 2026 Andrey Aleksandrov <aladex@gmail.com>

include $(TOPDIR)/rules.mk

PKG_NAME:=protonvpn-wireguard
PKG_VERSION:=0.3.2
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

# /etc/protonvpn holds runtime secrets that are not conffiles and cannot be
# regenerated locally: session.json (Proton UID + access/refresh tokens) and
# certificate.json (the key_seed of every instance's Ed25519 identity). Losing
# them forces a full SRP re-login, so they must survive a firmware upgrade —
# but they must not linger on disk once the package is gone.
define Package/protonvpn-wireguard/postrm
#!/bin/sh
# Only clean the live system, never a staging root, and never on upgrade
# (opkg passes "upgrade <ver>" as $$1; apk exports PKG_UPGRADE and runs
# pre-/post-upgrade instead of post-deinstall).
[ -n "$${IPKG_INSTROOT}" ] && exit 0
[ "$${PKG_UPGRADE}" = "1" ] && exit 0
case "$$1" in
	upgrade) exit 0 ;;
esac
rm -rf /etc/protonvpn
exit 0
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

	# Keep the runtime secret store (session + WireGuard certificates) across
	# sysupgrade; without this the user has to re-run the SRP login by hand.
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	echo "/etc/protonvpn/" > $(1)/lib/upgrade/keep.d/protonvpn

	$(INSTALL_DIR) $(1)/usr/share/ucode/protonvpn
	$(INSTALL_DATA) ./files/usr/share/ucode/protonvpn/*.uc $(1)/usr/share/ucode/protonvpn/
	$(SED) "s|^const VERSION = .*|const VERSION = '$(PKG_VERSION)-r$(PKG_RELEASE)';|" \
		$(1)/usr/share/ucode/protonvpn/common.uc

	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode
	$(INSTALL_DATA) ./files/usr/share/rpcd/ucode/protonvpn.uc $(1)/usr/share/rpcd/ucode/protonvpn.uc

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/protonvpn-apply $(1)/usr/bin/protonvpn-apply
	$(INSTALL_BIN) ./files/usr/bin/protonvpn-cache-update $(1)/usr/bin/protonvpn-cache-update
	$(INSTALL_BIN) ./files/usr/bin/protonvpn-rotate $(1)/usr/bin/protonvpn-rotate
	$(INSTALL_BIN) ./files/usr/bin/protonvpn-service $(1)/usr/bin/protonvpn-service
endef

$(eval $(call BuildPackage,protonvpn-wireguard))
