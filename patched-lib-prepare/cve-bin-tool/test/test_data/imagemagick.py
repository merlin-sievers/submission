# Copyright (C) 2025 Keysight Technologies
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "imagemagick",
        "version": "6.8.3",
        "version_strings": [
            "ImageMagick 6.8.3-2 2020-09-10 Q8 http://www.imagemagick.org"
        ],
    },
    {
        "product": "imagemagick",
        "version": "6.8.9",
        "version_strings": [
            "ImageMagick 6.8.9-10 Q8 x86_64 2024-08-30 http://www.imagemagick.org"
        ],
    },
]
package_test_data = [
    {
        "url": "https://ftp-stud.hs-esslingen.de/pub/Mirrors/sources.redhat.com/cygwin/x86_64/release/ImageMagick/libMagickCore6_6/",
        "package_name": "libMagickCore6_6-6.9.10.11-1.tar.xz",
        "product": "imagemagick",
        "version": "6.9.10",
        "other_products": ["gcc"],
    },
    {
        "url": "http://de.archive.ubuntu.com/ubuntu/pool/universe/i/imagemagick/",
        "package_name": "libmagickcore-6.q16hdri-7t64_6.9.13.12+dfsg1-1_amd64.deb",
        "product": "imagemagick",
        "version": "6.9.13",
    },
]
