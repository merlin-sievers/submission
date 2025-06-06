# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "uwsgi", "version": "2.0.18", "version_strings": ["2.0.18\nuwsgi"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/u/",
        "package_name": "uwsgi-2.0.28-4.fc42.aarch64.rpm",
        "product": "uwsgi",
        "version": "2.0.28",
    },
    {
        "url": "http://ftp.debian.org/debian/pool/main/u/uwsgi/",
        "package_name": "uwsgi-core_2.0.18-1_amd64.deb",
        "product": "uwsgi",
        "version": "2.0.18",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "uwsgi_2.0.18-1_x86_64.ipk",
        "product": "uwsgi",
        "version": "2.0.18",
    },
]
