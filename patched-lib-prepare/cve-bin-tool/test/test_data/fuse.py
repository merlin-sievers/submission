# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "fuse",
        "version": "2.9.9",
        "version_strings": ["2.9.9\nfusermount version"],
    }
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/f/",
        "package_name": "fuse-2.9.9-23.fc42.aarch64.rpm",
        "product": "fuse",
        "version": "2.9.9",
    },
    {
        "url": "http://ftp.debian.org/debian/pool/main/f/fuse/",
        "package_name": "fuse_2.9.9-5_amd64.deb",
        "product": "fuse",
        "version": "2.9.9",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "fuse-utils_2.9.7-2_x86_64.ipk",
        "product": "fuse",
        "version": "2.9.7",
    },
]
