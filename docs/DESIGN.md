# Technical Design

## Overview

BinHardS is a command-line tool that inspects compiled binaries for security mitigations and potentially insecure function usage.

The scanner operates on the compiled binary rather than source code. The current implementation supports ELF, PE, Mach-O, and detection of Mach-O fat binaries with limited analysis.

## Architecture

The implementation is centered on src/main.rs and src/analyzer.rs.

### CLI layer

src/main.rs defines the command-line interface with clap.

The current arguments are:

| Argument       | Description                                                       |
| -------------- | ---------------------------------------------------------------- |
| file           | Path to the binary to analyze.                                   |
| --json, -j     | Emit the analysis result as pretty-printed JSON.                  |
| --verbose, -v  | Print scanner and input-file information before analysis.         |

The CLI calls analyze_binary() and then either serializes the result as JSON or renders a human-readable report.

Errors are written to stderr and cause the process to exit with status 1.

## Binary analysis flow

1. Read the input file into memory.
2. Parse the byte buffer with goblin::Object::parse.
3. Identify the binary format.
4. Dispatch to the format-specific analysis logic.
5. Populate the shared AnalysisResults structure.
6. Render the result as text or JSON.

The format dispatch currently handles ELF, PE, Mach-O Binary, and Mach-O Fat objects. Other formats return an unsupported-format error.

## Result model

The analyzer returns AnalysisResults, which is serializable with Serde.

Its fields are file_path, format, nx, pie, stack_canary, relro, fortified_functions, and unprotected_functions.

MitigationStatus contains enabled and note fields. RelroStatus contains status and note. FunctionCheck contains count and symbols.

These structures define the current JSON output shape as well as the data consumed by the human-readable renderer.

## Format-specific checks

### ELF

The ELF analyzer checks NX through PT_GNU_STACK, PIE through ET_DYN, stack canaries through known stack-protection symbols, RELRO through PT_GNU_RELRO and DT_BIND_NOW, fortified symbols through __ and _chk name matching, and potentially dangerous functions through a configured symbol list.

### PE

The PE analyzer checks NX / DEP through IMAGE_DLLCHARACTERISTICS_NX_COMPAT, PIE / ASLR through IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, stack protection through Microsoft GS cookie symbols, and function findings through format-specific export/import name matching. RELRO is reported as N/A.

### Mach-O

The Mach-O analyzer checks NX through MH_ALLOW_STACK_EXECUTION, PIE through MH_PIE, stack canaries through known stack-checking symbols, and function findings through symbol-name matching. RELRO is reported as N/A.

### Mach-O fat binaries

Fat Mach-O files are recognized as Mach-O Fat. The current implementation does not select and analyze an individual architecture; it records notes that analysis is limited without architecture selection.

## Output modes

### Human-readable output

The default report includes the input file, detected format, NX, PIE, stack-canary, RELRO, fortified-function count, unprotected-function count, and unprotected symbols when present. Terminal colors are provided by colored.

### JSON output

--json serializes AnalysisResults with serde_json. This mode is intended for automation and CI/CD without requiring terminal-output parsing.

## Error handling

File-read failures and binary parsing failures are returned from analyze_binary() with contextual messages. Unsupported binary formats also produce an error. The CLI reports these errors to stderr and exits with a non-zero status.

## Testing

The analyzer contains unit tests for the default result structures: AnalysisResults, FunctionCheck, MitigationStatus, and RelroStatus.

Repository CI also exercises the built scanner against the scanner itself, system binaries such as /bin/ls and /bin/cat, a deliberately unsafe test program, and a hardened test program. CI also exercises JSON output.

## Design boundaries and current limitations

The current implementation is focused on binary inspection rather than source-level analysis.

- Analysis is based on binary metadata and symbols available to the parser; it does not prove every source-level security property.
- Mach-O fat binaries are detected but are not currently analyzed per architecture.
- RELRO is an ELF-specific check in the current implementation; PE and Mach-O report it as not applicable.
- Function checks are symbol-name based and depend on the configured function and symbol lists.
- The verbose value is accepted by the analyzer API but is currently used by the CLI rather than changing analyzer behavior.
- The result model represents mitigation state and notes, but does not expose a generalized finding/severity framework.

Changes to the scanner should preserve the distinction between what can be established from binary inspection and what would require source-level or runtime analysis.
