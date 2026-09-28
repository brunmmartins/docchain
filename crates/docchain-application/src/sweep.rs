//! Startup removal of never-committed ciphertext.
//!
//! The permit decides whether anything may be deleted; this module decides what. Every object
//! candidate that a complete reference read does not name, and every temporary candidate, is
//! debris. Nothing is removed before that read succeeds.

use std::{collections::BTreeSet, fmt, future::Future};

use docchain_domain::ObjectId;
use thiserror::Error;

use crate::StoreError;

/// Whether this start may delete debris.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SweepPermit {
    /// The server holds exclusive access to a root bound to its schema, and no earlier
    /// transaction on the schema is still open.
    Exclusive,
    /// The sweep deletes nothing, for this reason.
    Denied(SweepSkip),
}

/// Why a start skipped its sweep. Skipping is safe: nothing is deleted, and startup continues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SweepSkip {
    /// Another server holds the schema or the store root.
    ExclusivityNotObtained,
    /// The store root belongs to no schema and holds object or temporary names.
    StoreRootNotBound,
    /// A transaction on the schema stayed open past the drain bound.
    EarlierTransactionsOpen,
    /// The store root holds more entries than one sweep lists.
    InventoryOverBound,
}

impl SweepSkip {
    /// The fixed reason text, which names no object, path, or database identifier.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::ExclusivityNotObtained => "exclusivity not obtained",
            Self::StoreRootNotBound => "store root not bound",
            Self::EarlierTransactionsOpen => "earlier transactions still open",
            Self::InventoryOverBound => "inventory over bound",
        }
    }
}

/// One listing of the store root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inventory {
    /// Every entry was classified.
    Listed {
        /// Regular files named by an object ID.
        objects: BTreeSet<ObjectId>,
        /// Regular files named `.<object-id>.tmp`, keyed by that object ID.
        temporaries: BTreeSet<ObjectId>,
        /// Entries that are neither candidates nor control files.
        skipped: u64,
    },
    /// The root holds more entries than one sweep lists.
    OverBound,
}

/// One entry to remove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DebrisEntry {
    /// An object that no stored reference names.
    Object(ObjectId),
    /// The temporary file of an interrupted write.
    Temporary(ObjectId),
}

/// What one removal pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RemovedCounts {
    /// Objects removed.
    pub objects: u64,
    /// Temporary files removed.
    pub temporaries: u64,
    /// Entries left in place because they were no longer regular files.
    pub skipped: u64,
}

/// The outcome of the startup sweep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreSweep {
    /// The sweep ran to the end.
    Completed(SweepCounts),
    /// The sweep deleted nothing, for this reason.
    Skipped(SweepSkip),
}

/// Counts of a completed sweep: operational data only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepCounts {
    /// Unreferenced objects removed.
    pub removed_objects: u64,
    /// Temporary files removed.
    pub removed_temporaries: u64,
    /// Object candidates a stored reference names, kept.
    pub kept: u64,
    /// Entries neither removed nor kept: other names, other file types, or files that changed
    /// type before removal.
    pub skipped: u64,
}

impl fmt::Display for StoreSweep {
    /// Counts or a skip reason, never an object ID, path, or database identifier.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed(counts) => write!(
                formatter,
                "document store sweep: removed {} objects and {} temporary files; kept {} \
                 referenced objects; skipped {} entries",
                counts.removed_objects, counts.removed_temporaries, counts.kept, counts.skipped
            ),
            Self::Skipped(skip) => {
                write!(formatter, "document store sweep skipped: {}", skip.reason())
            }
        }
    }
}

/// Why a permitted sweep failed. Each failure deletes nothing further and fails startup.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SweepError {
    /// The store root could not be listed, or is no longer the root that was opened.
    #[error("document store inventory")]
    Inventory,
    /// The stored references could not all be read; nothing was removed.
    #[error("document store references")]
    References,
    /// Removal stopped on an error or its deadline; every entry removed was debris.
    #[error("document store sweep")]
    Removal,
}

/// Lists and removes debris candidates in the document store.
pub trait DebrisInventory: Send + Sync {
    /// Lists the store root once, within its entry and time bounds.
    fn inventory(&self) -> impl Future<Output = Result<Inventory, StoreError>> + Send;

    /// Removes each entry that is still a regular file, and never follows or removes anything
    /// else.
    fn remove_debris(
        &self,
        debris: &[DebrisEntry],
    ) -> impl Future<Output = Result<RemovedCounts, StoreError>> + Send;
}

/// Reads every stored object reference in one consistent snapshot.
pub trait ReferenceScan: Send + Sync {
    /// Returns the candidates that a stored reference names. It fails unless every stored
    /// reference was read and parsed.
    fn referenced_among(
        &self,
        candidates: &BTreeSet<ObjectId>,
    ) -> impl Future<Output = Result<BTreeSet<ObjectId>, StoreError>> + Send;
}

/// Removes never-committed ciphertext when the permit allows it.
///
/// A denied permit calls no port. A permitted sweep lists the root, then always reads every
/// stored reference, even with no candidates, and only then removes unreferenced objects and
/// every temporary file.
///
/// # Errors
///
/// [`SweepError::Inventory`] when listing fails, [`SweepError::References`] when the reference
/// read fails, in which case nothing is removed, and [`SweepError::Removal`] when removal fails.
///
/// # Cancellation
///
/// Dropping the future between steps removes nothing further. Every entry already removed was
/// debris, so a later permitted start resumes.
pub async fn sweep_debris<D: DebrisInventory, R: ReferenceScan>(
    permit: SweepPermit,
    documents: &D,
    references: &R,
) -> Result<StoreSweep, SweepError> {
    if let SweepPermit::Denied(skip) = permit {
        return Ok(StoreSweep::Skipped(skip));
    }
    let (objects, temporaries, listed_skipped) = match documents
        .inventory()
        .await
        .map_err(|_| SweepError::Inventory)?
    {
        Inventory::OverBound => return Ok(StoreSweep::Skipped(SweepSkip::InventoryOverBound)),
        Inventory::Listed {
            objects,
            temporaries,
            skipped,
        } => (objects, temporaries, skipped),
    };
    let referenced = references
        .referenced_among(&objects)
        .await
        .map_err(|_| SweepError::References)?;
    let kept = objects.intersection(&referenced).count();
    let debris: Vec<DebrisEntry> = objects
        .difference(&referenced)
        .cloned()
        .map(DebrisEntry::Object)
        .chain(temporaries.into_iter().map(DebrisEntry::Temporary))
        .collect();
    let removed = if debris.is_empty() {
        RemovedCounts::default()
    } else {
        documents
            .remove_debris(&debris)
            .await
            .map_err(|_| SweepError::Removal)?
    };
    Ok(StoreSweep::Completed(SweepCounts {
        removed_objects: removed.objects,
        removed_temporaries: removed.temporaries,
        kept: u64::try_from(kept).unwrap_or(u64::MAX),
        skipped: listed_skipped.saturating_add(removed.skipped),
    }))
}

#[cfg(test)]
mod tests;
