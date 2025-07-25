use goblin::Object;
use serde::Serialize;
use std::fs;

#[derive(Debug, Serialize)]
pub struct AnalysisResults {
    pub file_path: String,
    pub format: String,
    pub nx: MitigationStatus,
    pub pie: MitigationStatus,
    pub stack_canary: MitigationStatus,
    pub relro: RelroStatus,
    pub fortified_functions: FunctionCheck,
    pub unprotected_functions: FunctionCheck,
}

#[derive(Debug, Serialize, Default)]
pub struct MitigationStatus {
    pub enabled: bool,
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct RelroStatus {
    pub status: String,
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct FunctionCheck {
    pub count: usize,
    pub symbols: Vec<String>,
}

impl Default for AnalysisResults {
    fn default() -> Self {
        Self {
            file_path: String::new(),
            format: String::new(),
            nx: MitigationStatus {
                enabled: false,
                note: None,
            },
            pie: MitigationStatus {
                enabled: false,
                note: None,
            },
            stack_canary: MitigationStatus {
                enabled: false,
                note: None,
            },
            relro: RelroStatus {
                status: "None".to_string(),
                note: None,
            },
            fortified_functions: FunctionCheck {
                count: 0,
                symbols: vec![],
            },
            unprotected_functions: FunctionCheck {
                count: 0,
                symbols: vec![],
            },
        }
    }
}

pub fn analyze_binary(
    file_path: &str,
    _verbose: bool,
) -> Result<AnalysisResults, Box<dyn std::error::Error>> {
    let buffer =
        fs::read(file_path).map_err(|e| format!("Failed to read file {}: {}", file_path, e))?;

    let object = Object::parse(&buffer)
        .map_err(|e| format!("Failed to parse binary {}: {}", file_path, e))?;

    let mut results = AnalysisResults {
        file_path: file_path.to_string(),
        ..Default::default()
    };

    match object {
        Object::Elf(elf) => {
            results.format = "ELF".to_string();
            analyze_elf(&elf, &buffer, &mut results)?;
        }
        Object::PE(pe) => {
            results.format = "PE".to_string();
            analyze_pe(&pe, &buffer, &mut results)?;
        }
        Object::Mach(goblin::mach::Mach::Binary(mach)) => {
            results.format = "Mach-O".to_string();
            analyze_macho(&mach, &buffer, &mut results)?;
        }
        Object::Mach(goblin::mach::Mach::Fat(_fat)) => {
            results.format = "Mach-O Fat".to_string();
            results.nx.note = Some(
                "Fat binary detected. Analysis limited without specific architecture selection."
                    .to_string(),
            );
            results.pie.note = Some("Fat binary detected.".to_string());
            results.stack_canary.note = Some("Fat binary detected.".to_string());
            results.relro.note = Some("Fat binary detected.".to_string());
        }
        _ => {
            return Err(format!("Unsupported binary format for file: {}", file_path).into());
        }
    }

    Ok(results)
}

fn analyze_elf(
    elf: &goblin::elf::Elf,
    _buffer: &[u8],
    results: &mut AnalysisResults,
) -> Result<(), Box<dyn std::error::Error>> {
    let has_gnu_stack = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_STACK);

    if has_gnu_stack {
        results.nx.enabled = elf.program_headers.iter().any(|ph| {
            ph.p_type == goblin::elf::program_header::PT_GNU_STACK
                && (ph.p_flags & goblin::elf::program_header::PF_X) == 0
        });

        results.nx.note = if results.nx.enabled {
            Some("Stack is marked as non-executable".to_string())
        } else {
            Some("Stack is marked as executable".to_string())
        };
    } else {
        results.nx.enabled = false;
        results.nx.note =
            Some("No GNU_STACK segment found (may be executable by default)".to_string());
    }

    results.pie.enabled = elf.header.e_type == goblin::elf::header::ET_DYN;
    results.pie.note = if results.pie.enabled {
        Some("Binary is position independent (PIE enabled)".to_string())
    } else {
        Some("Binary has fixed load address (PIE disabled)".to_string())
    };

    let stack_symbols = [
        "__stack_chk_fail",
        "__stack_chk_guard",
        "__stack_smash_handler",
    ];

    let found_canary_symbols: Vec<String> = elf
        .syms
        .iter()
        .filter_map(|sym| {
            elf.strtab.get_at(sym.st_name).and_then(|name| {
                if stack_symbols.iter().any(|&s| name.contains(s)) {
                    Some(name.to_string())
                } else {
                    None
                }
            })
        })
        .collect();

    results.stack_canary.enabled = !found_canary_symbols.is_empty();
    results.stack_canary.note = if results.stack_canary.enabled {
        Some(format!(
            "Stack canaries detected: {}",
            found_canary_symbols.join(", ")
        ))
    } else {
        Some("No stack canary symbols found".to_string())
    };

    let mut relro_full = false;
    let mut relro_partial = false;

    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_GNU_RELRO {
            relro_partial = true;
            break;
        }
    }

    if relro_partial {
        if let Some(dynamic) = &elf.dynamic {
            relro_full = dynamic
                .dyns
                .iter()
                .any(|dyn_entry| dyn_entry.d_tag == goblin::elf::dynamic::DT_BIND_NOW);
        }
    }

    results.relro.status = if relro_full {
        "Full".to_string()
    } else if relro_partial {
        "Partial".to_string()
    } else {
        "None".to_string()
    };

    results.relro.note = Some(
        match results.relro.status.as_str() {
            "Full" => "Full RELRO: GOT is read-only after relocation",
            "Partial" => "Partial RELRO: Some sections are read-only after relocation",
            _ => "No RELRO: Global Offset Table is writable",
        }
        .to_string(),
    );

    let dangerous_functions = [
        "gets",
        "strcpy",
        "strcat",
        "sprintf",
        "vsprintf",
        "scanf",
        "fscanf",
        "sscanf",
        "vscanf",
        "vsscanf",
        "vfscanf",
        "strncpy",
        "strncat",
        "snprintf",
        "vsnprintf",
        "realpath",
        "getwd",
        "wcscpy",
        "wcscat",
        "wcsncat",
        "swprintf",
    ];

    let mut fortified_symbols = Vec::new();
    let mut unprotected_symbols = Vec::new();

    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if name.contains("__") && name.contains("_chk") {
                fortified_symbols.push(name.to_string());
            }

            if dangerous_functions.contains(&name) {
                unprotected_symbols.push(name.to_string());
            }
        }
    }

    results.fortified_functions = FunctionCheck {
        count: fortified_symbols.len(),
        symbols: fortified_symbols,
    };

    results.unprotected_functions = FunctionCheck {
        count: unprotected_symbols.len(),
        symbols: unprotected_symbols,
    };

    Ok(())
}

fn analyze_pe(
    pe: &goblin::pe::PE,
    _buffer: &[u8],
    results: &mut AnalysisResults,
) -> Result<(), Box<dyn std::error::Error>> {
    results.nx.enabled = if let Some(optional_header) = &pe.header.optional_header {
        (optional_header.windows_fields.dll_characteristics & 0x100) != 0 // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    } else {
        false
    };

    results.nx.note = if results.nx.enabled {
        Some("DEP (Data Execution Prevention) is enabled".to_string())
    } else {
        Some("DEP (Data Execution Prevention) is disabled".to_string())
    };

    results.pie.enabled = if let Some(optional_header) = &pe.header.optional_header {
        (optional_header.windows_fields.dll_characteristics & 0x40) != 0 // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    } else {
        false
    };

    results.pie.note = if results.pie.enabled {
        Some("ASLR (Address Space Layout Randomization) is enabled".to_string())
    } else {
        Some("ASLR is disabled - binary uses fixed base address".to_string())
    };

    let mut canary_found = false;
    let mut canary_symbols = Vec::new();

    for export in &pe.exports {
        if let Some(ref name) = export.name {
            if name.contains("__security_check_cookie")
                || name.contains("__security_cookie")
                || name.contains("@__security_check_cookie@")
            {
                canary_found = true;
                canary_symbols.push(name.to_string());
            }
        }
    }

    for import in &pe.imports {
        let import_name = import.name.as_ref();

        if import_name.contains("__security_check_cookie")
            || import_name.contains("__security_cookie")
        {
            canary_found = true;
            canary_symbols.push(format!("{}!{}", import.dll, import_name));
        }
    }

    results.stack_canary.enabled = canary_found;
    results.stack_canary.note = if canary_found {
        Some(format!(
            "Stack canaries (GS cookies) detected: {}",
            canary_symbols.join(", ")
        ))
    } else {
        Some("No stack canary (GS cookie) symbols found".to_string())
    };

    results.relro.status = "N/A".to_string();
    results.relro.note = Some(
        "RELRO is not applicable to PE format (Windows uses different memory protection)"
            .to_string(),
    );

    let dangerous_functions = [
        "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "fscanf", "sscanf", "vscanf",
        "vsscanf", "vfscanf", "strncpy", "strncat", "wcscpy", "wcscat", "StrCpy", "StrCat",
        "lstrcpy", "lstrcat", "StrCpyA", "StrCatA", "StrCpyW", "StrCatW",
    ];

    let mut fortified_symbols = Vec::new();
    let mut unprotected_symbols = Vec::new();

    for export in &pe.exports {
        if let Some(ref name) = export.name {
            if name.contains("_s") || name.contains("_chk") {
                fortified_symbols.push(name.to_string());
            }
            if dangerous_functions.contains(&name) {
                unprotected_symbols.push(name.to_string());
            }
        }
    }

    for import in &pe.imports {
        let import_name = import.name.as_ref();
        let full_name = format!("{}!{}", import.dll, import_name);

        if import_name.contains("_s") || import_name.contains("_chk") {
            fortified_symbols.push(full_name.clone());
        }

        if dangerous_functions.contains(&import_name) {
            unprotected_symbols.push(full_name);
        }
    }

    results.fortified_functions = FunctionCheck {
        count: fortified_symbols.len(),
        symbols: fortified_symbols,
    };

    results.unprotected_functions = FunctionCheck {
        count: unprotected_symbols.len(),
        symbols: unprotected_symbols,
    };

    Ok(())
}

fn analyze_macho(
    mach: &goblin::mach::MachO,
    _buffer: &[u8],
    results: &mut AnalysisResults,
) -> Result<(), Box<dyn std::error::Error>> {
    let has_allow_stack_execution = mach.header.flags & 0x20000 != 0; // MH_ALLOW_STACK_EXECUTION
    results.nx.enabled = !has_allow_stack_execution;
    results.nx.note = if results.nx.enabled {
        Some("Stack execution is not allowed".to_string())
    } else {
        Some("Stack execution may be allowed".to_string())
    };

    results.pie.enabled = mach.header.flags & 0x200000 != 0; // MH_PIE
    results.pie.note = if results.pie.enabled {
        Some("Position Independent Executable (PIE) is enabled".to_string())
    } else {
        Some("PIE is disabled - binary uses fixed load address".to_string())
    };

    let mut canary_found = false;
    let mut canary_symbols = Vec::new();

    for symbol_result in mach.symbols() {
        if let Ok((name, _symbol)) = symbol_result {
            if name.contains("__stack_chk_fail")
                || name.contains("__stack_chk_guard")
                || name.contains("___stack_chk_fail")
                || name.contains("___stack_chk_guard")
            {
                canary_found = true;
                canary_symbols.push(name.to_string());
            }
        }
    }

    results.stack_canary.enabled = canary_found;
    results.stack_canary.note = if canary_found {
        Some(format!(
            "Stack canaries detected: {}",
            canary_symbols.join(", ")
        ))
    } else {
        Some("No stack canary symbols found".to_string())
    };

    results.relro.status = "N/A".to_string();
    results.relro.note = Some(
        "RELRO not applicable to Mach-O (uses different memory protection mechanisms)".to_string(),
    );

    let dangerous_functions = [
        "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "fscanf", "sscanf", "vscanf",
        "vsscanf", "vfscanf", "strncpy", "strncat", "wcscpy", "wcscat", "realpath", "getwd",
    ];

    let mut fortified_symbols = Vec::new();
    let mut unprotected_symbols = Vec::new();

    for symbol_result in mach.symbols() {
        if let Ok((name, _symbol)) = symbol_result {
            if name.contains("_chk") || name.contains("__builtin___") {
                fortified_symbols.push(name.to_string());
            }

            let clean_name = name.trim_start_matches('_');
            if dangerous_functions.contains(&clean_name) {
                unprotected_symbols.push(name.to_string());
            }
        }
    }

    results.fortified_functions = FunctionCheck {
        count: fortified_symbols.len(),
        symbols: fortified_symbols,
    };

    results.unprotected_functions = FunctionCheck {
        count: unprotected_symbols.len(),
        symbols: unprotected_symbols,
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_analysis_results() {
        let results = AnalysisResults::default();
        assert_eq!(results.file_path, "");
        assert_eq!(results.format, "");
        assert_eq!(results.nx.enabled, false);
        assert_eq!(results.pie.enabled, false);
        assert_eq!(results.stack_canary.enabled, false);
        assert_eq!(results.relro.status, "None");
        assert_eq!(results.fortified_functions.count, 0);
        assert_eq!(results.unprotected_functions.count, 0);
    }

    #[test]
    fn test_function_check_default() {
        let fc = FunctionCheck::default();
        assert_eq!(fc.count, 0);
        assert_eq!(fc.symbols.len(), 0);
    }

    #[test]
    fn test_mitigation_status_default() {
        let ms = MitigationStatus::default();
        assert_eq!(ms.enabled, false);
        assert_eq!(ms.note, None);
    }

    #[test]
    fn test_relro_status_default() {
        let rs = RelroStatus::default();
        assert_eq!(rs.status, "None");
        assert_eq!(rs.note, None);
    }
}
