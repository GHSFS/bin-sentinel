// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod engine;
pub mod recipe;
pub mod types;

pub use engine::{diff_binaries, diff_files};
pub use recipe::{
    apply_recipe, generate_recipe, load_recipe_from_file, save_recipe_to_file, ApplyOptions,
};
pub use types::{
    ApplyReport, BinaryFormat, DiffHunk, DiffReport, MitigationChange, MitigationsDiff,
    PatchOperation, PatchRecipe, SectionDiff,
};
