mapping_test_data = [
    {
        "product": ".net",
        "version": "7.0.11",
        "version_strings": ["dotnet-v7.0.11"],
    },
    {
        "product": ".net",
        "version": "8.0.12",
        "version_strings": [
            "/8.0.12+89ef51c5d8f5239345127a1e282e11036e590c8b\nMicrosoft\n .NET\n"
        ],
    },
]

package_test_data = [
    {
        "url": "https://dl.fedoraproject.org/pub/fedora/linux/releases/39/Everything/aarch64/os/Packages/d/",
        "product": ".net",
        "version": "7.0.11",
        "package_name": "dotnet-runtime-7.0-7.0.11-1.fc39.aarch64.rpm",
        "other_products": ["clang"],
    },
    {
        "url": "http://security.ubuntu.com/ubuntu/pool/main/d/dotnet8/",
        "package_name": "dotnet-runtime-8.0_8.0.12-0ubuntu1~24.10.1_amd64.deb",
        "product": ".net",
        "version": "8.0.12",
        "other_products": ["clang"],
    },
]
