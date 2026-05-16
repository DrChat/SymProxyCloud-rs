use anyhow::Context;
use bitflags::bitflags;
use ms_pdb::{Pdb, ReadAt};
use serde::Deserialize;
use std::fmt;
use tracing::{info, warn};

/// PDB validation filter modes, analogous to symchk's PDB options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PdbFilter {
    /// Accept any PDB — just verify it exists and is a valid PDB (symchk `/pf` default).
    #[default]
    Any,
    /// Require private symbols and line data for code coverage.
    /// Equivalent to the debugger's "private symbols & lines" Load Report.
    Private,
    /// Verify that PDBs are stripped of source line, data type, and global information (`/ps`).
    Stripped,
    /// Verify that PDBs contain data type information (`/pt`).
    HasTypes,
}

impl fmt::Display for PdbFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PdbFilter::Any => write!(f, "any"),
            PdbFilter::Private => write!(f, "private"),
            PdbFilter::Stripped => write!(f, "stripped"),
            PdbFilter::HasTypes => write!(f, "has_types"),
        }
    }
}

impl std::str::FromStr for PdbFilter {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "any" | "pf" => Ok(PdbFilter::Any),
            "private" => Ok(PdbFilter::Private),
            "stripped" | "ps" => Ok(PdbFilter::Stripped),
            "has_types" | "pt" => Ok(PdbFilter::HasTypes),
            _ => anyhow::bail!(
                "invalid PDB filter '{}'. Valid values: any (pf), private, stripped (ps), has_types (pt)",
                s
            ),
        }
    }
}

/// DBI header flags bit for "private symbols have been stripped".
const DBI_FLAG_STRIPPED: u16 = 0x0002;

bitflags! {
    /// Describes what a PDB is *missing*.
    ///
    /// Each set bit means the PDB lacks a particular kind of information. A value of
    /// [`PdbFlags::empty()`] therefore means the PDB is fully populated (not stripped,
    /// has private symbols, line data, source info, and types).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PdbFlags: u32 {
        /// The DBI `fStripped` flag is set (private symbols were removed).
        const STRIPPED = 0b00001;
        /// No module stream contains private symbol data.
        const NO_PRIVATE_SYMS = 0b00010;
        /// No module stream contains line (C11/C13) data.
        const NO_LINE_DATA = 0b00100;
        /// The DBI stream carries no source-file information.
        const NO_SOURCE_INFO = 0b01000;
        /// The TPI stream carries no type records.
        const NO_TYPES = 0b10000;
    }
}

/// Inspect a PDB and report which kinds of information it is missing.
///
/// The returned [`PdbFlags`] has one bit set per absent category; an empty set means
/// the PDB is fully populated. Callers can then decide whether the PDB satisfies a
/// given [`PdbFilter`] by testing the relevant bits.
pub fn pdb_flags<F: ReadAt>(pdb: &Pdb<F>) -> anyhow::Result<PdbFlags> {
    let mut flags = PdbFlags::empty();

    if (pdb.dbi_header().flags.get() & DBI_FLAG_STRIPPED) != 0 {
        flags |= PdbFlags::STRIPPED;
    }

    let modules = pdb.modules().context("failed to read modules from PDB")?;

    // Single pass over the modules: look for any private symbols and any line data,
    // stopping early once both have been found.
    let (mut has_private_syms, mut has_line_data) = (false, false);
    for module in modules.iter() {
        let header = module.header();
        has_private_syms |= header.sym_byte_size.get() > 4;
        has_line_data |= header.c13_byte_size.get() > 0 || header.c11_byte_size.get() > 0;
        if has_private_syms && has_line_data {
            break;
        }
    }
    if !has_private_syms {
        flags |= PdbFlags::NO_PRIVATE_SYMS;
    }
    if !has_line_data {
        flags |= PdbFlags::NO_LINE_DATA;
    }

    if pdb.dbi_header().source_info_size.get() == 0 {
        flags |= PdbFlags::NO_SOURCE_INFO;
    }

    let tpi_header = pdb
        .tpi_header()
        .context("failed to read TPI header from PDB")?;
    if tpi_header.type_index_end() <= tpi_header.type_index_begin() {
        flags |= PdbFlags::NO_TYPES;
    }

    Ok(flags)
}

/// Validate a PDB via any [`ReadAt`] source (HTTP range reader, byte slice, etc.).
///
/// This avoids buffering the entire file; ms-pdb reads only the pages it needs
/// (~20-30 KB in 5-7 `read_at` calls).
///
/// Rather than inspecting the file's name, we attempt to open it as a PDB.
/// `Pdb::open_from_random_file` reads the header and fails if the file is not a
/// valid PDB, so anything that cannot be opened as a PDB simply fails validation.
pub fn validate_pdb_from_reader<F: ReadAt>(reader: F, filter: PdbFilter) -> anyhow::Result<bool> {
    let pdb = match Pdb::open_from_random_file(reader) {
        Ok(pdb) => pdb,
        Err(e) => {
            info!("file is not a valid PDB, failing validation: {e:#}");
            return Ok(false);
        }
    };
    validate_pdb_inner(*pdb, filter)
}

fn validate_pdb_inner<F: ReadAt>(pdb: Pdb<F>, filter: PdbFilter) -> anyhow::Result<bool> {
    if filter == PdbFilter::Any {
        return Ok(true);
    }

    // Reject FastLink/mini PDBs for all non-Any modes — they are incomplete.
    if pdb.mini_pdb() {
        warn!("PDB is a FastLink/mini PDB (requires original .obj files)");
        return Ok(false);
    }

    let flags = pdb_flags(&pdb)?;
    let result = filter_matches(flags, filter);

    if !result {
        info!(
            "PDB validation failed for filter '{}' (missing: {:?})",
            filter, flags
        );
    } else {
        info!("PDB validation passed for filter '{}'", filter);
    }

    Ok(result)
}

/// Decide whether a PDB with the given [`PdbFlags`] satisfies the requested
/// [`PdbFilter`]. This is the pure decision logic, independent of any PDB source.
fn filter_matches(flags: PdbFlags, filter: PdbFilter) -> bool {
    match filter {
        // Short-circuited before this function is reached in `validate_pdb_inner`.
        PdbFilter::Any => unreachable!("PdbFilter::Any handled earlier"),
        // Private symbols with lines: the PDB must be missing none of the bits that
        // indicate stripped/absent private symbol and line information.
        PdbFilter::Private => !flags
            .intersects(PdbFlags::STRIPPED | PdbFlags::NO_PRIVATE_SYMS | PdbFlags::NO_LINE_DATA),
        // Stripped: private symbols must be gone (either the flag is set or there are
        // none) and there must be no line data, source info, or types.
        PdbFilter::Stripped => {
            flags.intersects(PdbFlags::STRIPPED | PdbFlags::NO_PRIVATE_SYMS)
                && flags.contains(
                    PdbFlags::NO_LINE_DATA | PdbFlags::NO_SOURCE_INFO | PdbFlags::NO_TYPES,
                )
        }
        // Has types: the PDB must contain type information.
        PdbFilter::HasTypes => !flags.contains(PdbFlags::NO_TYPES),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_passes_only_when_fully_populated() {
        // An empty flag set means nothing is missing → passes Private.
        assert!(filter_matches(PdbFlags::empty(), PdbFilter::Private));
    }

    #[test]
    fn private_fails_when_any_required_bit_is_missing() {
        for missing in [
            PdbFlags::STRIPPED,
            PdbFlags::NO_PRIVATE_SYMS,
            PdbFlags::NO_LINE_DATA,
        ] {
            assert!(
                !filter_matches(missing, PdbFilter::Private),
                "Private should fail when {missing:?} is set"
            );
        }
    }

    #[test]
    fn private_ignores_source_info_and_types() {
        // Missing source info / types does not disqualify a Private PDB.
        let flags = PdbFlags::NO_SOURCE_INFO | PdbFlags::NO_TYPES;
        assert!(filter_matches(flags, PdbFilter::Private));
    }

    #[test]
    fn stripped_requires_private_gone_and_everything_else_absent() {
        // Private symbols removed (flag set) plus no line data, source info, or types.
        let flags = PdbFlags::STRIPPED
            | PdbFlags::NO_LINE_DATA
            | PdbFlags::NO_SOURCE_INFO
            | PdbFlags::NO_TYPES;
        assert!(filter_matches(flags, PdbFilter::Stripped));

        // Also valid when there simply are no private symbols instead of the flag.
        let flags = PdbFlags::NO_PRIVATE_SYMS
            | PdbFlags::NO_LINE_DATA
            | PdbFlags::NO_SOURCE_INFO
            | PdbFlags::NO_TYPES;
        assert!(filter_matches(flags, PdbFilter::Stripped));
    }

    #[test]
    fn stripped_fails_when_something_is_still_present() {
        // Missing the "private symbols gone" evidence.
        let flags = PdbFlags::NO_LINE_DATA | PdbFlags::NO_SOURCE_INFO | PdbFlags::NO_TYPES;
        assert!(!filter_matches(flags, PdbFilter::Stripped));

        // Private is gone, but line data is still present.
        let flags = PdbFlags::STRIPPED | PdbFlags::NO_SOURCE_INFO | PdbFlags::NO_TYPES;
        assert!(!filter_matches(flags, PdbFilter::Stripped));
    }

    #[test]
    fn has_types_depends_only_on_the_types_bit() {
        assert!(filter_matches(PdbFlags::empty(), PdbFilter::HasTypes));
        assert!(filter_matches(PdbFlags::STRIPPED, PdbFilter::HasTypes));
        assert!(!filter_matches(PdbFlags::NO_TYPES, PdbFilter::HasTypes));
    }
}
