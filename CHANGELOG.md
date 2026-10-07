# Changelog

All notable changes to BinHardS will be documented in this file.


## [0.1.1] - 2026-10-07



### Bug Fixes


- satisfy clippy lints
- preserve elf symbol lookup types
- satisfy clippy needless borrow
- satisfy clippy needless borrow
- restore elf symbol lookup borrow
- format changelog configuration
- analyze fat binary architectures (#1)
- remove obsolete cargo-release config


### CI


- modernize release readiness checks
- add tag-driven release validation
- enforce repository formatting rules
- restrict Taplo check to tracked TOML files
- publish releases with crates.io trusted publishing
- configure automated explicit releases
- configure changelog generation


### Chores


- add .gitignore
- update project metadata and ownership to ArbiSee
- configure dependency update checks
- add repository formatting configuration
- add repository formatting configuration
- add repository formatting configuration
- add repository formatting configuration
- bump actions/cache from 4 to 6
- bump actions/upload-artifact from 4 to 6
- bump actions/checkout from 4 to 7
- bump clap from 4.5.41 to 4.5.60
- bump serde_json from 1.0.141 to 1.0.151


### Documentation


- add contributor formatting guide
- add changelog
- document release process
- add technical design
- update documentation links
- format design document
- fix formatting of command-line arguments section


### Refactoring


- use interpolated strings for error messages and logging


### Testing


- cover Mach-O fat binaries (#1)


### style


- format release workflow with prettier


