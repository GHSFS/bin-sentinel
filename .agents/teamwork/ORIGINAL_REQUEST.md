# Original User Request

## 2026-10-13T03:19:35Z

This is a single self-contained fix; keep it small and focused.
Working directory: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\bin-sentinel
Integrity mode: development
Requirements:
R1: Implement Mach-O Universal and 64-bit binary parser (src/macho/) with support for 0xFEEDFACF and 0xCAFEBABE, LC_SEGMENT_64, LC_MAIN, LC_LOAD_DYLIB, LC_CODE_SIGNATURE, and section entropy.
R2: Add CLI command inspect-macho and synth-macho with human table and JSON outputs.
R3: Implement modular integration tests in tests/macho_test.rs.
R4: Verify zero-dependency pure Rust implementation and run check.mjs.
Acceptance Criteria: All tests pass, 0 clippy warnings, code under 300-500 lines per file.
