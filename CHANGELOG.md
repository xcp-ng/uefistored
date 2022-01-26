# Changelog
All notable changes to this project will be documented in this file.

## [1.1.3] - 2022-01-26

### Changed
- Drop all bufioreq logic
- Don't wait for ioreq server frames to appear

## [1.1.2] - 2021-10-28
### Added
- uefistored dies if certificates are misconfigured/missing
- uefistored doesn't wait for variable writes to update XAPI DB
- Add new `secureboot-certs extract` command.
- Add new `secureboot-certs --version` command.
- The secureboot-certs tool accepts all auth / cert formats
- secureboot-certs clearly indicates the file being downloaded
- secureboot-certs supports separate verbose and debug switches
- Improve secureboot-certs URL/HTTP error display

## [1.1.1] - 2021-08-13
### Fixed
- Fix build (Makefile)

## [1.1.0] - 2021-08-12
### Fixed
- Windows KB4535680 update now works.
- Build now works with GCC >= 11.0.0.

### Added
- Support for configuring the log level via /etc/uefistored/uefistored.conf.
- Format checking for secureboot-certs.
- No arguments resolves to default args in secureboot-certs.
- Logging presents certificate information when pkcs7 verification fails.

### Changed
- PK.auth is now opened from /var/lib/uefistored/PK.auth.
- If there is no default KEK or default db, then uefistored will not load the
  default PK.

## [1.0.0] - 2021-06-22
### Changed
- secureboot-certs: All arguments are now explicit and required!
  Calling secureboot-certs with no arguments will not work anymore.

### Added
- secureboot-certs: Support certificate sync via XAPI
- secureboot-certs: Support dbx

## [0.6.0] - 2021-05-10
### Added
- Support variable write appends

## [0.5.0] - 2021-03-30
### Added
- secureboot-certs allows local certs

### Fixed
- uefistored and secureboot-certs use /var/lib/uefistored
  for non-RPM managed certs (those made by secureboot-certs)

## [0.4.2] - 2021-03-23
### Fixed
- Build munit with -std=c99
- Use gzip for archive
- Fix bad path to create-auth in README

## [0.4.1] - 2021-11-23
### Fixed
- Fix abd path to create-auth tool

## [0.4.0] - 2021-03-03
### Security
- Use compiler barriers to prevent unsafe optimizations on shared memory data
- Use SMP memory barriers to ensure cross-CPU synchronicity of shared memory
  access
- Throttle requests to XAPI to prevent DoS of XAPI by guest
- Fix memory leaks

### Added
- scripts/secureboot-certs to automate Microsoft cert installation for users
- Better docs in README.md
- Load arbitrary certs (no trust chain required) from dom0 via auth files

### Changed
- Change .auth path to /usr/share/uefistored/ instead of /usr/share/varstored/
- Abstract backend interface to support various (or no) backend
- Remove hardcoded XAPI dependency (XAPI not used if --backend does not equal
  xapidb)
- The unit tests are no longer bitrotted and now use ASAN
- Major code cleanup

## [0.3.1] - 2021-01-11
### Changed
- Increased max variable data size to 32KB (required by Microsoft)
- Due to the increased data size, dynamic memory wass re-introduced
- Remove more OVMF-style code, dead code

### Fixed
- Make query variable calculate available space based on slots
- Compiler flags: -O2,  stack protection, etc...

## [0.3.0] - 2020-12-04
### Added
- Support Secure Boot
    - Support KEK
    - Support db
    - Support dbx
- Harden sandbox with seccomp, rlimits, deprivileging

### Changed
- Code refactoring for simplicity and style upkeep
- Further reduced dynamic memory usage

### Fixed
- Filter RO variables on GUID

## [0.2.6] - 2020-11-20
### Fixed
- Prevent infinite load on restored Windows backups (issue #454)

## [0.2.5] - 2020-11-9
### Changed
- Push all auth vars through auth service pipeline (not based only on attrs)

## [0.2.4] - 2020-11-2
### Changed
- Log to daemon.log instead of /var/log/uefistored/

## [0.2.3] - 2020-10-29
### Added
- Support PK exchange
- PK.auth is now opened from /usr/share/varstored/PK.auth
- Unit tests for PK implementation
- Test scripts for PK (valid and invalid certs)

### Changed
- Preserve backwards compatibility with varstored

## [0.2.2] - 2020-10-21
### Changed
- Fix no RT access variable bug (now supporting Windows Server 2016 boot)

## [0.2.1] - 2020-10-12
### Changed
- Disable debug by default in build

## [0.2.0] - 2020-10-12
### Added
- Support generic authenticated variables
- Use PK to marshall UEFI into correct boot state
- Use Vates key for default PK

### Changed
- Fix race causing failed boot
- Fix GetNextVariable() bug when reported buffer size was off by one on utf16 names
- Minimize dynamic memory in variable management
- Improve code style on request parsing
- Eliminate redundant / legacy abstractions

## [0.1.1] - 2020-08-20
### Added
- Support volatile variables
- Add log message header

### Changed
- Code clean up
- Use more defensive coding checks

## [0.1.0] - 2020-08-19
### Added
- Initialize uefistored as device model with VMs, compliant with XAPI calls
- Support XAPI xml calls
- Support handling of guest UEFI requests
- Support minimal sandboxing via chroot jail

[0.3.1]: https://github.com/xcp-ng/uefistored/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/xcp-ng/uefistored/compare/v0.2.6...v0.3.0
[0.2.6]: https://github.com/xcp-ng/uefistored/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/xcp-ng/uefistored/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/xcp-ng/uefistored/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/xcp-ng/uefistored/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/xcp-ng/uefistored/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/xcp-ng/uefistored/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/xcp-ng/uefistored/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/xcp-ng/uefistored/compare/v0.1...v0.1.1
[0.1.0]: https://github.com/xcp-ng/uefistored/releases/tag/v0.1.0
