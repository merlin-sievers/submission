# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "subversion",
        "version": "1.13.0",
        "version_strings": [
            r"subversion-1.13.0",
            r"Working copy locked; if no other Subversion client is currently using the working copy, try running 'svn cleanup' without the --remove",
            r"Working copy locked; try running 'svn cleanup' on the root of the working copy ('%s') instead.",
        ],
    },
    {
        "product": "subversion",
        "version": "1.14.2",
        "version_strings": [
            r"@(#)1.14.2 (r1899510)",
        ],
    },
]
package_test_data = [
    {
        "url": "http://ports.ubuntu.com/pool/main/s/subversion/",
        "package_name": "subversion_1.9.3-2ubuntu1_arm64.deb",
        "product": "subversion",
        "version": "1.9.3",
    },
    {
        "url": "http://ftp.debian.org/debian/pool/main/s/subversion/",
        "package_name": "libsvn1_1.14.1-3+deb11u1_arm64.deb",
        "product": "subversion",
        "version": "1.14.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "subversion-libs_1.12.2-2_x86_64.ipk",
        "product": "subversion",
        "version": "1.12.2",
    },
    {
        "url": "https://mirror.msys2.org/msys/x86_64/",
        "package_name": "subversion-1.14.2-8-x86_64.pkg.tar.zst",
        "product": "subversion",
        "version": "1.14.2",
        "other_products": ["gcc"],
    },
]
