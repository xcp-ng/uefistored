# Changelog
All notable changes to this project will be documented in this file.

## [Unreleased]
- Add changelog
- Support Secure Boot
    - Support PK
    - Support KEK
    - Support db
    - Support dbx
- Harden sandbox with seccomp and rlimits
- Support variable write appends

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

[0.2.1]: https://github.com/xcp-ng/uefistored/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/xcp-ng/uefistored/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/xcp-ng/uefistored/compare/v0.1...v0.1.1
[0.1.0]: https://github.com/xcp-ng/uefistored/releases/tag/v0.1.0
