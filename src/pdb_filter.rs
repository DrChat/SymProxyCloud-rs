use anyhow::Context;
use bitflags::bitflags;
use ms_pdb::{Pdb, ReadAt};
use serde::Deserialize;

/// PDB validation filter modes, analogous to symchk's PDB options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PdbFilter {
    /// Allow both public and private PDBs (`/pa`)
    #[default]
    Any,
    /// Verify that PDB files contain full source information (`/pf`)
    Private,
    /// Verify that PDB files are stripped and do not contain full source (private) information (`/ps`).
    Stripped,
    /// Verify that PDB files are stripped, but do have type information.  Some
    /// PDB files may be stripped but have type information added back in (`/pt`).
    HasTypes,
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

/// Decide whether a PDB with the given [`PdbFlags`] satisfies the requested
/// [`PdbFilter`].
pub fn filter_matches(flags: PdbFlags, filter: PdbFilter) -> bool {
    match filter {
        PdbFilter::Any => true,
        PdbFilter::Private => flags.is_empty(),
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
