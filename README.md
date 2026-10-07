# BinHardS - Binary Hardening Scanner

[![CI](https://github.com/arbiseeos/binhards/actions/workflows/ci.yml/badge.svg)](https://github.com/arbiseeos/binhards/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A CLI tool to inspect compiled binaries (ELF, PE, Mach-O) for security mitigations and insecure patterns.

## Table of Contents

1. [Project Title](#binary-hardening-scanner)
2. [Overview](#overview)
3. [Features](#features)
4. [Getting Started](#getting-started)
5. [Usage](#usage)
6. [Documentation](#documentation)
7. [Contributing](#contributing)
8. [Roadmap](#roadmap)
9. [Community & Support](#community--support)
10. [Security](#security)
11. [License](#license)
12. [Acknowledgments](#acknowledgments)

## Overview

The Binary Hardening Scanner is a developer-facing security tool designed to inspect compiled binaries for critical security mitigations and insecure coding patterns. It directly addresses the common issue of typos or omissions in compiler flags that can silently disable essential protections.

This tool helps developers and security engineers:

- Verify that security features like NX, PIE, Stack Canaries, and RELRO are enabled in their binaries.
- Identify potentially dangerous function calls (e.g., `gets`, `strcpy`) that could lead to vulnerabilities.
- Catch missing fortified library function calls that could indicate incomplete hardening.
- Integrate security checks into CI/CD pipelines to catch build configuration errors early.

The scanner operates on the final compiled binary, making it language-agnostic and suitable for any development workflow.

## Features

- **Cross-Platform Support**: Analyzes ELF (Linux), PE (Windows), and Mach-O (macOS) binaries
- **Security Mitigation Checks**:
  - NX (No-eXecute) / DEP (Data Execution Prevention)
  - PIE (Position Independent Executable) / ASLR (Address Space Layout Randomization)
  - Stack Canaries
  - RELRO (RELocation Read-Only) - for ELF binaries
- **Function Analysis**:
  - Detects fortified library functions (`__chk` variants)
  - Flags potentially dangerous functions (`gets`, `strcpy`, etc.)
- **CI/CD Integration**: JSON output option for easy integration into automated pipelines
- **Developer-Friendly Output**: Clear, colorized terminal output with detailed notes
- **Language Agnostic**: Works with binaries compiled from any programming language

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (toolchain for building)
- For testing with compiled binaries: GCC/Clang (Linux), Visual Studio (Windows), Xcode (macOS)

### Installation

#### From Source

```bash
git clone https://github.com/arbiseeos/binhards.git
cd binhards
cargo build --release
```

The binary will be available at `target/release/binhards`.

#### Using Cargo

```bash
cargo install binhards
```

### Running

After building:

```bash
# Analyze a binary
./target/release/binhards /path/to/binary

# Get JSON output for CI/CD
./target/release/binhards --json /path/to/binary

# Verbose output
./target/release/binhards --verbose /path/to/binary
```

## Usage

### Basic Analysis

```bash
# Analyze a Linux ELF binary
binhards /bin/ls

# Analyze a Windows PE binary (on Windows or with Wine)
binhards myapp.exe

# Analyze a macOS Mach-O binary (on macOS)
binhards /Applications/MyApp.app/Contents/MacOS/MyApp
```

### CI/CD Integration

```bash
# In a CI script, fail if critical mitigations are missing
if ! binhards --json myapp | jq -e '.nx.enabled == true and .pie.enabled == true' > /dev/null; then
  echo "Critical security mitigations are missing!"
  exit 1
fi
```

### Example Output

```
BinHardS Scanner Report
File: /bin/ls
Format: ELF

Security Mitigations:
  NX (No-eXecute): ENABLED
    Note: Stack is marked as non-executable
  PIE (Position Independent Executable): ENABLED
    Note: Binary is position independent (PIE enabled)
  Stack Canary: ENABLED
    Note: Stack canaries detected: __stack_chk_fail
  RELRO (RELocation Read-Only): FULL
    Note: Full RELRO: GOT is read-only after relocation

Fortified Functions:
  Fortified functions detected: 5
  Unprotected functions detected: 0
```

## Documentation

Detailed documentation is available in the project repository:

- [Technical Design](docs/DESIGN.md)
- [Development Guide](docs/DEVELOPMENT.md)
- [API Reference](docs/API.md)

For information on how security mitigations work, see:

- [GCC Security Hardening Flags](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)
- [Microsoft Compiler Security Checks](https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check)

## Contributing

We welcome contributions from the community!

- [CONTRIBUTING.md](https://github.com/arbiseeos/.github/blob/main/CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](https://github.com/arbiseeos/.github/blob/main/CODE_OF_CONDUCT.md)

### Development Setup

1. Install Rust toolchain
2. Clone the repository
3. Run tests: `cargo test`
4. Build: `cargo build`
5. Run: `cargo run -- /path/to/binary`

Please open an issue first to discuss significant changes.

## Roadmap

Planned enhancements:

- Enhanced PE analysis for additional Windows security features (Control Flow Guard, etc.)
- Improved Mach-O fat binary handling for multi-architecture analysis
- Plugin system for custom checks
- Performance optimizations for large binary analysis
- Integration with popular CI/CD platforms (GitHub Actions, GitLab CI, etc.)

See [GitHub Issues](https://github.com/arbiseeos/binhards/issues) for current development tasks and enhancements.

## Community & Support

- Discussions: [GitHub Discussions](https://github.com/arbiseeos/binhards/discussions)
- Issues: [GitHub Issues](https://github.com/arbiseeos/binhards/issues)
- For general questions, please use GitHub Discussions

## Security

We take security seriously. If you discover a security vulnerability within this project, please follow our [Security Policy](https://github.com/arbiseeos/.github/blob/main/SECURITY.md) to report it responsibly.

- Please report security issues to: `security@os.arbisee.com`
- [SECURITY.md](https://github.com/arbiseeos/.github/blob/main/SECURITY.md)

## License

This project is licensed under the [MIT License](./LICENSE).

## Acknowledgments

- Built with [Rust](https://www.rust-lang.org/)
- Binary parsing powered by [goblin](https://crates.io/crates/goblin)
- Inspired by security research on compiler flag typos and binary hardening tools like [checksec](https://github.com/slimm609/checksec.sh) and [BinSkim](https://github.com/microsoft/binskim)
