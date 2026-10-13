// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{RichRecord, RichToolKind};

/// Maps a 16-bit MSVC Product ID to a known tool name and categorized kind.
pub fn lookup_tool(product_id: u16) -> (&'static str, RichToolKind) {
    match product_id {
        0x0000 => ("Unknown", RichToolKind::Other),
        0x0001 => ("Import0", RichToolKind::ImportExport),
        0x0002 => ("Linker", RichToolKind::Linker),
        0x0003 => ("Cvtres", RichToolKind::ResourceCompiler),
        0x0004 => ("Utc13_2_C", RichToolKind::CCompiler),
        0x0005 => ("Utc13_2_CPP", RichToolKind::CppCompiler),
        0x0006 => ("Utc13_2_C_POGO", RichToolKind::CCompiler),
        0x0007 => ("Utc13_2_CPP_POGO", RichToolKind::CppCompiler),
        0x000A => ("Masm613", RichToolKind::Assembler),
        0x000B => ("Masm710", RichToolKind::Assembler),
        0x000E => ("Export", RichToolKind::ImportExport),
        0x000F => ("Implib", RichToolKind::ImportExport),
        0x0014 => ("Cvpack", RichToolKind::Other),
        0x0017 => ("AliasObj", RichToolKind::ImportExport),
        0x0019 => ("Cvtomf", RichToolKind::Other),
        0x001E => ("Utc13_0_C", RichToolKind::CCompiler),
        0x001F => ("Utc13_0_CPP", RichToolKind::CppCompiler),
        0x0026 => ("Utc13_10_C", RichToolKind::CCompiler),
        0x0027 => ("Utc13_10_CPP", RichToolKind::CppCompiler),
        0x005D => ("Masm800", RichToolKind::Assembler),
        0x006B => ("Utc14_0_C", RichToolKind::CCompiler),
        0x006C => ("Utc14_0_CPP", RichToolKind::CppCompiler),
        0x0078 => ("Utc15_0_C", RichToolKind::CCompiler),
        0x0079 => ("Utc15_0_CPP", RichToolKind::CppCompiler),
        0x0083 => ("Linker900", RichToolKind::Linker),
        0x0084 => ("Cvtres900", RichToolKind::ResourceCompiler),
        0x0092 => ("Cvtres1000", RichToolKind::ResourceCompiler),
        0x0093 => ("Utc16_0_C", RichToolKind::CCompiler),
        0x0094 => ("Utc16_0_CPP", RichToolKind::CppCompiler),
        0x0095 => ("Masm1000", RichToolKind::Assembler),
        0x0097 => ("Linker1000", RichToolKind::Linker),
        0x0098 => ("Export1000", RichToolKind::ImportExport),
        0x00A2 => ("Cvtres1100", RichToolKind::ResourceCompiler),
        0x00A3 => ("Utc17_0_C", RichToolKind::CCompiler),
        0x00A4 => ("Utc17_0_CPP", RichToolKind::CppCompiler),
        0x00A5 => ("Masm1100", RichToolKind::Assembler),
        0x00A7 => ("Linker1100", RichToolKind::Linker),
        0x00C4 => ("Cvtres1200", RichToolKind::ResourceCompiler),
        0x00C5 => ("Utc18_0_C", RichToolKind::CCompiler),
        0x00C6 => ("Utc18_0_CPP", RichToolKind::CppCompiler),
        0x00C7 => ("Masm1200", RichToolKind::Assembler),
        0x00C9 => ("Linker1200", RichToolKind::Linker),
        0x00E7 => ("Cvtres1400", RichToolKind::ResourceCompiler),
        0x00E8 => ("Export1400", RichToolKind::ImportExport),
        0x00EA => ("Utc19_00_C", RichToolKind::CCompiler),
        0x00EB => ("Utc19_00_CPP", RichToolKind::CppCompiler),
        0x00EC => ("Masm1400", RichToolKind::Assembler),
        0x00EE => ("Linker1400", RichToolKind::Linker),
        0x00F4 => ("Cvtres1410", RichToolKind::ResourceCompiler),
        0x00F5 => ("Export1410", RichToolKind::ImportExport),
        0x00F6 => ("Utc19_10_C", RichToolKind::CCompiler),
        0x00F7 => ("Utc19_10_CPP", RichToolKind::CppCompiler),
        0x00F8 => ("Masm1410", RichToolKind::Assembler),
        0x00FA => ("Linker1410", RichToolKind::Linker),
        0x00FF => ("Implib1420", RichToolKind::ImportExport),
        0x0101 => ("Cvtres1420", RichToolKind::ResourceCompiler),
        0x0102 => ("Linker1420", RichToolKind::Linker),
        0x0103 => ("Utc19_20_C", RichToolKind::CCompiler),
        0x0104 => ("Utc19_20_CPP", RichToolKind::CppCompiler),
        0x0105 => ("Masm1420", RichToolKind::Assembler),
        0x010D => ("Export1420", RichToolKind::ImportExport),
        0x0121 => ("Cvtres1430", RichToolKind::ResourceCompiler),
        0x0122 => ("Linker1430", RichToolKind::Linker),
        0x0123 => ("Utc19_30_C", RichToolKind::CCompiler),
        0x0124 => ("Utc19_30_CPP", RichToolKind::CppCompiler),
        0x0125 => ("Masm1430", RichToolKind::Assembler),
        0x012D => ("Export1430", RichToolKind::ImportExport),
        _ => ("Unknown_Tool", RichToolKind::Other),
    }
}

/// Resolves the human-readable Visual Studio suite name based on build number and product ID.
pub fn resolve_vs_version(product_id: u16, build_number: u16) -> &'static str {
    match build_number {
        7000..=7999 => "Visual Studio 97 (v5.0)",
        8000..=8999 => "Visual Studio 6.0 (v6.0)",
        9000..=9999 => "Visual Studio .NET 2002 (v7.0)",
        3077 => "Visual Studio .NET 2003 (v7.1)",
        50727 => "Visual Studio 2005 (v8.0)",
        21022 | 30729 => "Visual Studio 2008 (v9.0)",
        30319 | 40219 => "Visual Studio 2010 (v10.0)",
        51106 | 60610 | 61030 => "Visual Studio 2012 (v11.0)",
        21005 | 31101 | 40629 => "Visual Studio 2013 (v12.0)",
        23026 | 23506 | 24210 | 24213 | 24215 => "Visual Studio 2015 (v14.0)",
        25019 | 26430 | 26726 | 27023 => "Visual Studio 2017 (v14.1)",
        27412 | 28803 | 29112 | 29915 | 30037 | 30133 => "Visual Studio 2019 (v14.2)",
        31329 | 31631 | 32532 | 33130 | 34000..=49999 => "Visual Studio 2022 (v14.3)",
        _ => {
            // Heuristic by product ID ranges if build number is non-standard or zero
            match product_id {
                0x0004..=0x0007 | 0x000A | 0x000B => "Visual Studio .NET (v7.x)",
                0x006B | 0x006C => "Visual Studio 2005 (v8.0)",
                0x0078 | 0x0079 | 0x0083 | 0x0084 => "Visual Studio 2008 (v9.0)",
                0x0092..=0x0098 => "Visual Studio 2010 (v10.0)",
                0x00A2..=0x00A7 => "Visual Studio 2012 (v11.0)",
                0x00C4..=0x00C9 => "Visual Studio 2013 (v12.0)",
                0x00E7..=0x00EE => "Visual Studio 2015 (v14.0)",
                0x00F4..=0x00FA => "Visual Studio 2017 (v14.1)",
                0x00FF..=0x010D => "Visual Studio 2019 (v14.2)",
                0x0121..=0x012D => "Visual Studio 2022 (v14.3)",
                _ => "Unknown Toolset",
            }
        }
    }
}

/// Identifies the dominant primary toolchain suite represented in the given records.
pub fn determine_primary_toolchain(records: &[RichRecord]) -> String {
    if records.is_empty() {
        return "No Rich Tool Records".to_string();
    }

    let mut vs2022_count = 0;
    let mut vs2019_count = 0;
    let mut vs2017_count = 0;
    let mut vs2015_count = 0;
    let mut vs2013_count = 0;
    let mut vs2012_count = 0;
    let mut vs2010_count = 0;
    let mut vs2008_count = 0;
    let mut legacy_count = 0;

    for r in records {
        if r.vs_version.contains("2022") {
            vs2022_count += r.count;
        } else if r.vs_version.contains("2019") {
            vs2019_count += r.count;
        } else if r.vs_version.contains("2017") {
            vs2017_count += r.count;
        } else if r.vs_version.contains("2015") {
            vs2015_count += r.count;
        } else if r.vs_version.contains("2013") {
            vs2013_count += r.count;
        } else if r.vs_version.contains("2012") {
            vs2012_count += r.count;
        } else if r.vs_version.contains("2010") {
            vs2010_count += r.count;
        } else if r.vs_version.contains("2008") {
            vs2008_count += r.count;
        } else if !r.vs_version.contains("Unknown") {
            legacy_count += r.count;
        }
    }

    let max_count = vs2022_count
        .max(vs2019_count)
        .max(vs2017_count)
        .max(vs2015_count)
        .max(vs2013_count)
        .max(vs2012_count)
        .max(vs2010_count)
        .max(vs2008_count)
        .max(legacy_count);

    if max_count == 0 {
        return "Unknown Visual Studio Suite".to_string();
    }

    if max_count == vs2022_count {
        "Visual Studio 2022 (v14.3)".to_string()
    } else if max_count == vs2019_count {
        "Visual Studio 2019 (v14.2)".to_string()
    } else if max_count == vs2017_count {
        "Visual Studio 2017 (v14.1)".to_string()
    } else if max_count == vs2015_count {
        "Visual Studio 2015 (v14.0)".to_string()
    } else if max_count == vs2013_count {
        "Visual Studio 2013 (v12.0)".to_string()
    } else if max_count == vs2012_count {
        "Visual Studio 2012 (v11.0)".to_string()
    } else if max_count == vs2010_count {
        "Visual Studio 2010 (v10.0)".to_string()
    } else if max_count == vs2008_count {
        "Visual Studio 2008 (v9.0)".to_string()
    } else {
        "Legacy Visual Studio Suite".to_string()
    }
}
