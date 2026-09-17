# SPDX-License-Identifier: MIT
# Copyright 2026 Andrey Aleksandrov <aladex@gmail.com>

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-protonvpn
PKG_VERSION:=0.7.1
PKG_RELEASE:=1
PKG_MAINTAINER:=Andrey Aleksandrov <aladex@gmail.com>
PKG_LICENSE:=MIT

LUCI_TITLE:=LuCI support for ProtonVPN WireGuard
LUCI_DESCRIPTION:=Web interface for the ProtonVPN WireGuard backend (protonvpn-wireguard): \
	SRP login in the browser, runtime status, server selection, automatic \
	rotation and cache management. Unofficial; not affiliated with Proton AG.
LUCI_DEPENDS:=+luci-base +protonvpn-wireguard
LUCI_PKGARCH:=all

include ../../luci.mk

# call BuildPackage - OpenWrt buildroot signature
