# Third-Party Notices

The release ZIP redistributes the following third-party components.
The module scripts (`customize.sh`, `service.sh`, `action.sh`,
`uninstall.sh`, `scripts/castctl-ctl`, `build.sh`) are covered by the
repository `LICENSE` (GPL-3.0-or-later).

## castctl

- Version: 0.6.4
- Upstream: https://github.com/thoitiettxl-cyber/castctl
- Binary asset: `castctl_0.6.4_linux_arm64.tar.gz`
- Binary SHA-256: `311696a8d3693b9510269ffd59f679070009e20cf81bbc3696ad9b2f67114c71`
- License: GPL-3.0-or-later; see `LICENSE`, `LICENSE.sing-box`, `NOTICE`
  included in the ZIP.

## GNU C Library for Android/Termux

- Package version: 2.44
- Package: `glibc_2.44_aarch64.deb`
- Package SHA-256: `5392d254e84c436e96783bcb6ffffe429d6b24c7ad00490f23f06f66c4769fb6`
- Package repository: https://packages-cf.termux.dev/apt/termux-glibc/
- Android patch/build recipe snapshot:
  https://github.com/termux/glibc-packages/tree/954c6b200aa001088fcc420550b9304dd81229b8/gpkg/glibc
- GNU glibc 2.44 source archive:
  https://ftp.gnu.org/gnu/libc/glibc-2.44.tar.xz
- Source archive SHA-256: `37f600f2bef3c5e8300147059568b2a2e40a7ad6ccc65ce942556d49429cc667`
  (carried from the template's provenance record; not re-verified here)
- License: GNU Lesser General Public License 2.1 or later; see
  `licenses/GLIBC-COPYING.LESSERv2`.

Only the dynamic loader and the explicitly listed shared libraries in
`payload-manifest.txt` are copied from the glibc package into the module.

## Alpine CA certificate bundle

- Package: `ca-certificates-bundle-20261020-r0`
- Packaged file: `/etc/ssl/cert.pem` (extracted from the pinned `.apk`)
- File SHA-256: `5961c0a3c65459931c023e0075c09733f09aea4ca439cb85bc4a08bb4f3f568b`
- Mozilla certificate policy:
  https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/

## Module structure template

The module's structure and conventions follow the KernelSU module in
https://github.com/thoitiettxl-cyber/cli-proxy-api at commit
`f912a733f84a3157e6570d84c05e5a02439d3ff0`. No code from that repository
is redistributed except `META-INF/com/google/android/update-binary`
(the generic Magisk/KernelSU installer entry point, copied verbatim)
and the LGPL license text in `licenses/`. All other scripts were
written for castctl following the template's patterns; the deviations
are listed in `docs/ksu-module.md`.
