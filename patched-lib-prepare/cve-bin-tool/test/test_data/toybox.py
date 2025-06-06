# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "toybox", "version": "0.8.9", "version_strings": ["toybox\n0.8.9"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/openmandriva/5.0/repository/aarch64/unsupported/release/",
        "package_name": "toybox-0.7.7-1-omv4000.aarch64.rpm",
        "product": "toybox",
        "version": "0.7.7",
        "other_products": ["gcc"],
    },
    {
        "url": "http://ftp.debian.org/debian/pool/main/t/toybox/",
        "package_name": "toybox_0.8.9+dfsg-1.1_amd64.deb",
        "product": "toybox",
        "version": "0.8.9",
    },
]
