#!/usr/bin/env python3

from cve_bin_tool.version_compare import Version  # pyright:ignore[reportMissingTypeStubs]
from src.openssl import OpenSSLBuilder
from src.version import TaggedVersion

b = OpenSSLBuilder(version = TaggedVersion(Version("3.0.0"), OpenSSLBuilder.get_tag_for_version("3.0.0")), toolchain="arm-linux-gnueabi")
