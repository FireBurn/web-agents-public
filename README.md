## OpenAM Web Policy Agents
[![Latest release](https://img.shields.io/github/release/OpenIdentityPlatform/OpenAM-Web-Agents.svg)](https://github.com/OpenIdentityPlatform/OpenAM-Web-Agents/releases)
[![Build](https://github.com/OpenIdentityPlatform/OpenAM-Web-Agents/actions/workflows/build.yml/badge.svg)](https://github.com/OpenIdentityPlatform/OpenAM-Web-Agents/actions/workflows/build.yml)
[![Issues](https://img.shields.io/github/issues/OpenIdentityPlatform/OpenAM-Web-Agents.svg)](https://github.com/OpenIdentityPlatform/OpenAM-Web-Agents/issues)
[![Last commit](https://img.shields.io/github/last-commit/OpenIdentityPlatform/OpenAM-Web-Agents.svg)](https://github.com/OpenIdentityPlatform/OpenAM-Web-Agents/commits/master)
[![License](https://img.shields.io/badge/license-CDDL--1.0-blue.svg)](https://github.com/OpenIdentityPlatform/OpenAM-Web-Agents/blob/master/LICENSE.md)
[![Gitter](https://img.shields.io/gitter/room/nwjs/nw.js.svg)](https://gitter.im/OpenIdentityPlatform/OpenAM)
[![Top language](https://img.shields.io/github/languages/top/OpenIdentityPlatform/OpenAM-Web-Agents.svg)](https://github.com/OpenIdentityPlatform/OpenAM-Web-Agents)
[![Code size](https://img.shields.io/github/languages/code-size/OpenIdentityPlatform/OpenAM-Web-Agents.svg)](https://github.com/OpenIdentityPlatform/OpenAM-Web-Agents)

OpenAM Web Policy Agents is an OpenAM add-on component that functions as a Policy Enforcement Point (PEP) for applications deployed behind a web server. It protects web-based applications and provides single sign-on (SSO) for services running in the container.

Supported servers:
- Apache HTTP Server 2.4 (Linux, macOS)
- Microsoft IIS (Windows)

## License
Licensed under the [Common Development and Distribution License v1.0 (CDDL-1.0)](https://github.com/OpenIdentityPlatform/OpenAM-Web-Agents/blob/master/LICENSE.md). Files carry an SPDX identifier (`SPDX-License-Identifier: CDDL-1.0`) rather than the full CDDL boilerplate header.

## Downloads
Pre-built binaries for each tagged release are attached to the corresponding [GitHub Release](https://github.com/OpenIdentityPlatform/OpenAM-Web-Agents/releases), built automatically by CI:

- `OpenAM-WebAgent-Linux.zip` — Ubuntu LTS (Apache 2.4)
- `OpenAM-WebAgent-RHEL-{7,8,9,10}.zip` — RHEL / AlmaLinux / CentOS Stream
- `OpenAM-WebAgent-macOS.zip` — macOS (Apache 2.4 via Homebrew)
- `OpenAM-WebAgent-Windows.zip` — Windows x64 (IIS)

## Building from source

The build uses **CMake (≥ 3.10)**. The old `build.xml` Ant-based build has been removed.

### Dependencies

| Platform | Install command |
|----------|-----------------|
| Debian / Ubuntu | `sudo apt-get install -y cmake libpcre2-dev libexpat1-dev zlib1g-dev libzip-dev libssl-dev apache2-dev` |
| RHEL / AlmaLinux / Fedora | `sudo dnf install -y cmake gcc make pcre2-devel expat-devel zlib-devel libzip-devel openssl-devel httpd-devel` |
| macOS (Homebrew) | `brew install cmake pcre2 expat zlib libzip openssl@3 httpd` |
| Windows (vcpkg) | `vcpkg install pcre2:x64-windows expat:x64-windows zlib:x64-windows libzip:x64-windows openssl:x64-windows` |

Additionally, `clang-format` is recommended if you intend to contribute patches (see [Contributing](#contributing)).

### Build (Linux / macOS)
```bash
git clone https://github.com/OpenIdentityPlatform/OpenAM-Web-Agents.git
cd OpenAM-Web-Agents
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

On macOS with Homebrew OpenSSL, export its root so CMake can find it:
```bash
export OPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
```

### Build (Windows)
```powershell
cmake -B build -DCMAKE_BUILD_TYPE=Release `
      -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake" `
      -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build --config Release -j
```

### Build outputs
After building you'll find:
- `build/libopenam.{so,dylib}` / `build/openam.dll` — core agent shared library
- `build/agentadmin[.exe]` — admin / packaging tool
- `build/mod_openam.{so,dylib}` — Apache module (where `apxs` was detected)
- `build/mod_iis_openam.dll` — IIS module (Windows only)

## Releasing

Releases are driven entirely by tag pushes.

1. Bump `AGENT_VERSION` in `CMakeLists.txt` if needed.
2. Tag and push:
   ```bash
   git tag -a 5.0.0 -m "Release 5.0.0"
   git push origin 5.0.0
   ```
3. CI builds every platform in the matrix, creates a GitHub Release for the tag with auto-generated notes, and attaches the zipped artifacts.

Tags must start with a digit (e.g. `5.0.0`, `5.0.1-rc1`). Non-tag pushes run build + tests only.

## Contributing

Pull requests are welcome: <https://github.com/OpenIdentityPlatform/OpenAM-Web-Agents/pulls>

### Code formatting

The project enforces formatting with `clang-format`; see [`.clang-format`](.clang-format). CI rejects any PR whose C / header files aren't formatted.

**Recommended setup**: install [pre-commit](https://pre-commit.com) and let it run the formatter automatically on every commit:
```bash
pip install pre-commit
pre-commit install
```

Once installed, `git commit` will format staged C/H files before accepting the commit. To run against the whole tree manually:
```bash
pre-commit run --all-files
```

If you'd rather not use the framework, you can run `clang-format` directly:
```bash
find source tests integration -type f \( -name '*.c' -o -name '*.h' \) -exec clang-format -i {} +
```

### License headers

All new C / header files should start with:
```c
// SPDX-License-Identifier: CDDL-1.0
//
// Copyright <year> <your name or org>.
```

When modifying existing files, append your own copyright line below the existing ones; do not remove or alter prior copyright attributions.

## Support

- Community wiki: <https://github.com/OpenIdentityPlatform/OpenAM-Web-Agents/wiki>
- Mailing list: open-identity-platform-openam@googlegroups.com
- Archive: <https://groups.google.com/d/forum/open-identity-platform-openam>
- Gitter chat: <https://gitter.im/OpenIdentityPlatform/OpenAM>
- Commercial support: support@openam.org.ru (English, Russian)

## Thanks

This project stands on the shoulders of:
- Sun Access Manager
- Sun OpenSSO
- Oracle OpenSSO
- ForgeRock OpenAM
