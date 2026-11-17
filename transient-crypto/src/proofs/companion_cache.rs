// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Trusted mmap companion publication and the opt-in parameter provider.

use super::{ParamsLoadPolicy, ParamsProver, ParamsProverProvider};
use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use std::{io, sync::Arc};

/// Proof that a directory's published companions will not change while this
/// process maps them.
///
/// Constructing one of these **is** the memory-safety obligation for
/// memory-mapped parameters, and it is the only place that obligation is taken
/// on. Everything downstream — [`CompanionCache`], [`MappedParams`] — accepts
/// this value and is safe, because the promise has already been made by
/// someone who was in a position to make it.
///
/// That is the difference from the version this replaces. Before, a safe
/// `get_params` asserted the property itself, on a directory that came from
/// `MIDNIGHT_PP` or `XDG_CACHE_HOME`, on behalf of callers it had never seen.
/// A comment claiming "this is our own cache directory" is a statement about
/// intent; it cannot establish anything about a path an environment variable
/// chose.
#[derive(Clone, Debug)]
pub struct TrustedParamsDir(std::path::PathBuf);

impl TrustedParamsDir {
    /// Promise that `dir` holds only immutable published companions.
    ///
    /// # Safety
    ///
    /// For as long as this value, any clone of it, and any [`ParamsProver`]
    /// obtained through it are alive, no party — this process or any other —
    /// may modify, truncate, or replace the contents of a published companion
    /// in `dir`. `memmap2` states that in- or out-of-process modification of a
    /// mapped file makes use of the map undefined behaviour, and the typed
    /// slices handed out from a mapped companion are exactly that use.
    ///
    /// An application's own private cache directory qualifies, and the caller
    /// is the one who knows whether theirs is. A world-writable directory, a
    /// user-editable one, a network or cloud-synced folder, and anywhere a
    /// companion arrives from another party do not.
    ///
    /// Declining to call this is always sound: parameters then load eagerly,
    /// which costs memory and time and nothing else.
    ///
    /// ```compile_fail
    /// // The promise cannot be made without an `unsafe` block, so a mapped
    /// // companion cannot be reached by safe code at all.
    /// use midnight_transient_crypto::proofs::TrustedParamsDir;
    /// let _ = TrustedParamsDir::new("/tmp");
    /// ```
    #[allow(unsafe_code)]
    pub unsafe fn new(dir: impl Into<std::path::PathBuf>) -> Self {
        Self(dir.into())
    }

    /// The directory this promise was made about.
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

/// Wraps a parameter provider so that published mmap companions in a
/// [`TrustedParamsDir`] are used when present.
///
/// This is opt-in by construction: a provider that is not wrapped never maps a
/// file, whatever is on disk and whatever the environment says. Wrapping is
/// safe, because the obligation was discharged when the `TrustedParamsDir` was
/// built.
///
/// On a miss the call falls through to the wrapped provider. An explicit
/// [`ParamsLoadPolicy`] can also publish and reopen the missing companion.
/// Neither choice changes the parameter value.
pub struct MappedParams<P> {
    inner: P,
    dir: TrustedParamsDir,
    policy: ParamsLoadPolicy,
}

impl<P> MappedParams<P> {
    /// Use companions already published in `dir`, falling back to `inner` on
    /// a miss. Building a new companion must be requested explicitly.
    pub fn new(inner: P, dir: TrustedParamsDir) -> Self {
        Self::with_policy(inner, dir, ParamsLoadPolicy::default())
    }

    /// Use an explicit parameter-load policy for this provider instance.
    /// The build choice is captured here rather than read from the process
    /// environment during a proof request.
    pub fn with_policy(inner: P, dir: TrustedParamsDir, policy: ParamsLoadPolicy) -> Self {
        Self { inner, dir, policy }
    }

    /// The provider this one falls back to.
    pub fn inner(&self) -> &P {
        &self.inner
    }
}

impl<P: ParamsProverProvider> ParamsProverProvider for MappedParams<P> {
    async fn get_params(&self, k: u8) -> io::Result<ParamsProver> {
        let name = base_crypto::data_provider::MidnightDataProvider::name_k(k);
        let cache = CompanionCache::from_trusted_dir(self.dir.clone());

        // A published companion: zero-copy. `ParamsKZG.g` / `g_lagrange`
        // become slice views into the file mapping, and the OS pages handle
        // eviction under memory pressure.
        if let Some(mapped) = cache.open(&name)? {
            tracing::info!(target: "midnight_bench", stage = "load_mmap", k = k as u64);
            return Ok(mapped);
        }

        // Build one on first miss when this provider's policy requests it: the
        // build briefly pays the 2x eager-load peak, holding the just-parsed
        // parameters while writing their bytes out. Concurrent first builders
        // are fine — the cache publishes by atomic rename with one winner, and
        // a loser opens the winner's complete file.
        if self.policy.build_mmap_companion {
            tracing::info!(target: "midnight_bench", stage = "build_mmap_companion", k = k as u64);
            let params = self.inner.get_params_with_policy(k, self.policy).await?;
            return cache.open_or_build(&name, || Ok(params));
        }

        self.inner.get_params_with_policy(k, self.policy).await
    }
}

/// What [`CompanionCache::publish_file`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Our bytes were validated and now sit under the final name.
    Published,
    /// Another publisher won the rename; our temp file was discarded and the
    /// winner's complete file is the one to open.
    AlreadyPublished,
}

/// Publish SRS companions without replacing a mapped inode, and open them
/// only through an explicitly trusted directory.
///
/// A companion (`<name>.mmap`) is a memory-mapped cache of an SRS. Mapping is
/// only sound while the mapped file is never modified or truncated, so the
/// cache enforces the discipline the rest of this crate relies on:
///
/// - **A published inode is never rewritten.** Bytes go to a uniquely named
///   private temp file in the same directory, are `sync_all`ed, and then reach
///   the final name by *one* atomic rename that refuses to replace an existing
///   file (`persist_noclobber`). Nothing this crate does can
///   shorten a file some other mapping holds.
/// - **Concurrent first builders have one winner.** Every builder writes its
///   own temp file; the first rename wins, every other publisher gets
///   [`PublishOutcome::AlreadyPublished`], drops its temp file and opens the
///   winner's complete file. No lock file, no partial header: a reader that
///   sees the final name sees complete bytes, which the reader validates,
///   because the name appears only after the rename.
/// - **Crash recovery is cleanup, not repair.** A crash before the rename
///   leaves a `.<name>.mmap.tmp-*` file behind; the next publisher removes
///   temp files older than [`Self::STALE_TEMP_AGE`] before it starts. A crash
///   after the rename left a complete file. The directory entry is fsynced
///   after publication on Unix so the rename itself is durable.
///
/// # Trust boundary
///
/// The guarantee above is against *this crate*: nothing here writes to a
/// published companion. It cannot be a guarantee against every other process,
/// and documentation cannot impose that obligation on a safe constructor — so
/// it does not try to. Opening a companion requires a cache built with
/// [`CompanionCache::from_trusted_dir`], which is `unsafe`, and the caller
/// carries the obligation named there.
///
/// Publishing parameters produced by this crate stays safe through
/// [`CompanionCache::publish_params_into`]. The generic publication hook is
/// unsafe because its callback can retain a cloned file handle while the
/// validator maps the temporary file.
#[derive(Clone, Debug)]
pub struct CompanionCache {
    dir: std::path::PathBuf,
}

impl CompanionCache {
    /// Temp files older than this are treated as left by a crashed
    /// publisher and removed before a new publication starts. An hour is far
    /// beyond any companion write; a live publisher's temp file is seconds
    /// old.
    pub const STALE_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

    const TEMP_INFIX: &'static str = ".tmp-";

    /// A cache rooted at a directory whose companions will not change.
    ///
    /// Safe, and deliberately so: the obligation lives in
    /// [`TrustedParamsDir`], whoever built that value has already made the
    /// promise, and this function only carries it. There is exactly one
    /// `unsafe` in the chain from an environment variable to a live mapping,
    /// and it is at the point where a caller named the directory.
    ///
    /// Publishing known parameters needs none of this —
    /// [`Self::publish_params_into`] takes a plain path and never maps the
    /// temporary file. The generic publication hook has its own unsafe
    /// callback contract.
    pub fn from_trusted_dir(trusted: TrustedParamsDir) -> Self {
        Self {
            dir: trusted.path().to_path_buf(),
        }
    }

    /// The directory companions are published into.
    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// Where the companion for the SRS called `name` lives once published.
    ///
    /// Fails with [`io::ErrorKind::InvalidInput`] unless the resulting file
    /// name is a single ordinary path component. `PathBuf::join` discards the
    /// cache root when handed an absolute path, and `..` walks out of it, so an
    /// unchecked name would let a safe call reach any file on the system —
    /// which is the capability [`Self::from_trusted_dir`] is `unsafe` about.
    pub fn published_path(&self, name: &str) -> io::Result<std::path::PathBuf> {
        // Both halves, because neither implies the other. `..` composes to the
        // harmless-looking `...mmap` and would pass a check on the composed
        // name alone, while `../x` composes to `../x.mmap` and would pass a
        // check on the SRS name alone if it were a suffix that made it escape.
        Self::check_component(std::ffi::OsStr::new(name))?;
        let file_name = Self::file_name(name);
        Self::check_component(std::ffi::OsStr::new(&file_name))?;
        Ok(self.dir.join(file_name))
    }

    fn file_name(name: &str) -> String {
        format!("{name}.mmap")
    }

    /// Accept only a single ordinary path component: no separator of either
    /// platform's kind, no `.` or `..`, no root or prefix, not empty.
    fn check_component(name: &std::ffi::OsStr) -> io::Result<()> {
        use std::path::Component;
        let reject = |why: &str| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("companion name {name:?} {why}"),
            )
        };
        let text = name.to_string_lossy();
        if text.is_empty() {
            return Err(reject("is empty"));
        }
        if text.contains(std::path::is_separator) || text.contains('\\') {
            return Err(reject("contains a path separator"));
        }
        let mut components = std::path::Path::new(name).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(only)), None) if only == name => Ok(()),
            _ => Err(reject("is not a single ordinary path component")),
        }
    }

    /// The prefix every temp file for `file_name` carries: hidden, and unique
    /// enough that a sweep cannot touch anything else in the directory.
    fn temp_prefix(file_name: &std::ffi::OsStr) -> String {
        format!(".{}{}", file_name.to_string_lossy(), Self::TEMP_INFIX)
    }

    /// Open the published companion for `name`, or `Ok(None)` when none is
    /// published yet. A file that exists is complete by construction; a file
    /// that fails validation is reported as `InvalidData`, never mapped.
    pub fn open(&self, name: &str) -> io::Result<Option<ParamsProver>> {
        let path = self.published_path(name)?;
        match std::fs::File::open(&path) {
            Ok(file) => Self::map_published(&file).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Open the published companion for `name`, building and publishing it
    /// first when there is none. `build` produces the eager parameters to
    /// publish; it may run in more than one process at once, and only one
    /// result is published — the others are discarded and their callers open
    /// the winner's file.
    pub fn open_or_build(
        &self,
        name: &str,
        build: impl FnOnce() -> io::Result<ParamsProver>,
    ) -> io::Result<ParamsProver> {
        if let Some(mapped) = self.open(name)? {
            return Ok(mapped);
        }
        let published_path = self.published_path(name)?;
        let eager = build()?;
        let file_name = Self::file_name(name);
        Self::publish_params_into(&self.dir, std::ffi::OsStr::new(&file_name), &eager)?;
        drop(eager);
        self.open(name)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "companion {} disappeared between publication and open",
                    published_path.display()
                ),
            )
        })
    }

    /// Publish arbitrary companion bytes through a temporary mapped validator.
    ///
    /// # Safety
    ///
    /// The callback must not retain or share a handle to the temporary file,
    /// and no other writer may alter it while validation maps it. See
    /// [`Self::publish_into`] for the full contract.
    ///
    /// For parameters produced by this crate use [`Self::publish_params_into`].
    #[allow(unsafe_code)]
    pub unsafe fn publish_file(
        &self,
        file_name: &std::ffi::OsStr,
        write: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
    ) -> io::Result<PublishOutcome> {
        unsafe { Self::publish_into(&self.dir, file_name, write) }
    }

    /// Publish `file_name` into `dir`, validating arbitrary bytes with a
    /// temporary mmap before no-clobber publication.
    ///
    /// `file_name` must be a single ordinary path component; see
    /// [`Self::published_path`].
    ///
    /// # Safety
    ///
    /// The callback must not retain or share a handle to the temporary file,
    /// and no other writer may modify or truncate that file while validation
    /// maps it. A callback can call `File::try_clone`, so this condition cannot
    /// be enforced by a safe generic API. Use a private directory that excludes
    /// other writers. The map is dropped before the final name is published.
    #[allow(unsafe_code)]
    pub unsafe fn publish_into(
        dir: &std::path::Path,
        file_name: &std::ffi::OsStr,
        write: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
    ) -> io::Result<PublishOutcome> {
        Self::publish_impl(dir, file_name, write, Self::validate)
    }

    /// Publish bytes generated from an existing parameter value. This safe
    /// path has no externally supplied writer and does not map its temporary
    /// file. The trusted writer's format is also exercised by round-trip tests.
    pub(crate) fn publish_params_into(
        dir: &std::path::Path,
        file_name: &std::ffi::OsStr,
        params: &ParamsProver,
    ) -> io::Result<PublishOutcome> {
        Self::publish_impl(
            dir,
            file_name,
            |file| params.0.write_mmap_companion(file),
            |_| Ok(()),
        )
    }

    fn publish_impl(
        dir: &std::path::Path,
        file_name: &std::ffi::OsStr,
        write: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
        validate: impl FnOnce(&std::fs::File) -> io::Result<()>,
    ) -> io::Result<PublishOutcome> {
        Self::check_component(file_name)?;
        let final_path = dir.join(file_name);
        if final_path.exists() {
            return Ok(PublishOutcome::AlreadyPublished);
        }
        Self::sweep_stale_temps_in(dir, file_name);

        let prefix = Self::temp_prefix(file_name);
        let mut temp = tempfile::Builder::new().prefix(&prefix).tempfile_in(dir)?;
        // `NamedTempFile` removes the file on drop, so every early return
        // below — including the `?`s — leaves no temp file behind.
        write(temp.as_file_mut())?;
        temp.as_file().sync_all()?;
        validate(temp.as_file())?;

        match temp.persist_noclobber(&final_path) {
            Ok(_) => {
                Self::sync_dir_at(dir);
                Ok(PublishOutcome::Published)
            }
            Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => {
                // `e.file` is the temp file; dropping it removes it.
                Ok(PublishOutcome::AlreadyPublished)
            }
            Err(e) => Err(e.error),
        }
    }

    /// Run the reader's header validation over a file we alone hold, before
    /// it can be published. A companion that would fail to open is never
    /// given a name a reader could find.
    #[allow(unsafe_code)]
    fn validate(file: &std::fs::File) -> io::Result<()> {
        // SAFETY: `file` is our private, unpublished temp file — no other
        // party has its name, and this function holds the only mapping for
        // the duration of the check. The mapping is dropped before the rename.
        let mmap = unsafe { memmap2::Mmap::map(file)? };
        // SAFETY: the unpublished temp file remains private and unchanged
        // until the returned params are dropped at the end of this call.
        unsafe { ParamsKZG::<Bls12>::read_mmap_arc(Arc::new(mmap)) }.map(|_| ())
    }

    /// Map a companion this cache published. The soundness argument is the
    /// cache's: nothing in this crate rewrites a published inode, and the
    /// directory is one where only cooperating code writes (type-level trust
    /// boundary).
    #[allow(unsafe_code)]
    fn map_published(file: &std::fs::File) -> io::Result<ParamsProver> {
        // SAFETY: see above — published companions are immutable by
        // construction of this type, which is the invariant `Mmap::map` asks
        // for; the cache directory's write access is the stated trust boundary.
        let mmap = unsafe { memmap2::Mmap::map(file)? };
        // SAFETY: published companions are never rewritten in place; the
        // cache directory admits only cooperating writers.
        Ok(ParamsProver(Arc::new(unsafe {
            ParamsKZG::read_mmap_arc(Arc::new(mmap))?
        })))
    }

    /// Remove temp files for `file_name` left by a publisher that did not
    /// reach its rename. Age-gated so a live publisher's file is never
    /// touched; failures are ignored — a stale temp file is harmless, and the
    /// publication that follows does not depend on the sweep.
    fn sweep_stale_temps_in(dir: &std::path::Path, file_name: &std::ffi::OsStr) {
        let prefix = Self::temp_prefix(file_name);
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let now = std::time::SystemTime::now();
        for entry in entries.flatten() {
            let candidate = entry.file_name();
            if !candidate.to_string_lossy().starts_with(&prefix) {
                continue;
            }
            let stale = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age >= Self::STALE_TEMP_AGE);
            if stale {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// Make the directory entry durable after a publication. Best effort:
    /// filesystems that cannot fsync a directory still have the complete file,
    /// only its name may not survive a power loss — which the next publisher
    /// repairs by publishing again.
    fn sync_dir_at(dir: &std::path::Path) {
        #[cfg(unix)]
        {
            if let Ok(dir) = std::fs::File::open(dir) {
                let _ = dir.sync_all();
            }
        }
    }
}

#[cfg(test)]
mod tests;
