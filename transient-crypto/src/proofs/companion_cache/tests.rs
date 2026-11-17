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

use super::*;
use midnight_proofs::utils::SerdeFormat;
use std::io::Write;
use std::sync::Barrier;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

const NAME: &str = "bls_test_2p4";

fn small_params() -> ParamsProver {
    ParamsProver(Arc::new(ParamsKZG::<Bls12>::unsafe_setup(
        4,
        rand::rngs::OsRng,
    )))
}

fn digest(p: &ParamsProver) -> Vec<u8> {
    let mut bytes = Vec::new();
    p.0.write_custom(&mut bytes, SerdeFormat::RawBytesUnchecked)
        .expect("serialise params");
    bytes
}

fn temps_in(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("read cache dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp-"))
        .collect()
}

#[test]
fn nothing_published_opens_as_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = CompanionCache::from_trusted_dir(unsafe { TrustedParamsDir::new(dir.path()) });
    assert!(cache.open(NAME).expect("open").is_none());
    assert!(!cache.published_path(NAME).expect("valid name").exists());
}

#[test]
fn concurrent_first_builders_share_one_complete_publication() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = small_params();
    let expected = digest(&source);
    let builds = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let cache =
                CompanionCache::from_trusted_dir(unsafe { TrustedParamsDir::new(dir.path()) });
            let source = source.clone();
            let builds = Arc::clone(&builds);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                cache.open_or_build(NAME, || {
                    builds.fetch_add(1, AtomicOrdering::SeqCst);
                    Ok(source)
                })
            })
        })
        .collect();
    for h in handles {
        let mapped = h.join().expect("thread").expect("open_or_build");
        assert_eq!(digest(&mapped), expected, "every caller sees the same SRS");
    }
    assert!(builds.load(AtomicOrdering::SeqCst) >= 1);
    assert!(cache_has_exactly_one_published(dir.path()));
    assert!(
        temps_in(dir.path()).is_empty(),
        "no temp file survives publication"
    );
}

fn cache_has_exactly_one_published(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir)
        .expect("read cache dir")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".mmap"))
        .count()
        == 1
}

#[test]
fn a_published_companion_is_never_rewritten_while_mapped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = CompanionCache::from_trusted_dir(unsafe { TrustedParamsDir::new(dir.path()) });
    let first = small_params();
    let mapped = cache
        .open_or_build(NAME, || Ok(first.clone()))
        .expect("first publication");
    let path = cache.published_path(NAME).expect("valid name");
    let bytes_before = std::fs::read(&path).expect("read companion");

    // A second, different SRS asks to be written to the same path while
    // `mapped` is alive. It must be refused without touching the inode.
    let second = small_params();
    let err = second
        .write_mmap_companion(&path)
        .expect_err("a published companion must not be rewritten");
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
    assert_eq!(
        std::fs::read(&path).expect("re-read"),
        bytes_before,
        "bytes unchanged"
    );
    assert_eq!(
        digest(&mapped),
        digest(&first),
        "the live mapping still reads the first SRS"
    );
    assert!(temps_in(dir.path()).is_empty());
}

#[test]
fn a_reader_racing_a_builder_sees_a_complete_file_or_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = small_params();
    let expected = digest(&source);
    let barrier = Arc::new(Barrier::new(5));
    let builder = {
        let cache = CompanionCache::from_trusted_dir(unsafe { TrustedParamsDir::new(dir.path()) });
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            cache.open_or_build(NAME, || Ok(source))
        })
    };
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let cache =
                CompanionCache::from_trusted_dir(unsafe { TrustedParamsDir::new(dir.path()) });
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                // Wait until the name appears; every success must be a
                // complete, validated file — `open` never returns a
                // partial one because the name is created by the rename.
                // A fixed spin count can expire before the builder is even
                // scheduled on a busy CI host.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while std::time::Instant::now() < deadline {
                    match cache.open(NAME) {
                        Ok(Some(p)) => return Ok(p),
                        Ok(None) => std::thread::sleep(std::time::Duration::from_millis(1)),
                        Err(e) => return Err(e),
                    }
                }
                Err(io::Error::other("reader gave up"))
            })
        })
        .collect();
    builder.join().expect("builder thread").expect("build");
    for r in readers {
        let p = r
            .join()
            .expect("reader thread")
            .expect("reader must not see a partial file");
        assert_eq!(digest(&p), expected);
    }
}

#[test]
fn a_write_failure_publishes_nothing_and_leaves_no_temp() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = CompanionCache::from_trusted_dir(unsafe { TrustedParamsDir::new(dir.path()) });
    // SAFETY: the callback retains no handle and the test owns the directory.
    let outcome = unsafe {
        cache.publish_file(std::ffi::OsStr::new("k4.mmap"), |file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("injected write failure"))
        })
    };
    let err = outcome.expect_err("injected failure must propagate");
    assert_eq!(err.to_string(), "injected write failure");
    assert!(!dir.path().join("k4.mmap").exists());
    assert!(temps_in(dir.path()).is_empty());
}

#[test]
fn a_short_write_fails_validation_and_publishes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = CompanionCache::from_trusted_dir(unsafe { TrustedParamsDir::new(dir.path()) });
    let full = {
        let mut buf = Vec::new();
        small_params()
            .0
            .write_mmap_companion(&mut buf)
            .expect("write");
        buf
    };
    let half = &full[..full.len() / 2];
    // SAFETY: the callback retains no handle and the test owns the directory.
    let err =
        unsafe { cache.publish_file(std::ffi::OsStr::new("k4.mmap"), |file| file.write_all(half)) }
            .expect_err("a truncated companion must not be published");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    assert!(!dir.path().join("k4.mmap").exists());
    assert!(temps_in(dir.path()).is_empty());
}

#[test]
fn a_rename_failure_publishes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache_dir = dir.path().join("cache");
    std::fs::create_dir(&cache_dir).expect("mkdir");
    let cache = CompanionCache::from_trusted_dir(unsafe { TrustedParamsDir::new(&cache_dir) });
    let cache_dir_for_hook = cache_dir.clone();
    // SAFETY: the callback retains no handle and the test owns the directory.
    let err = unsafe {
        cache.publish_file(std::ffi::OsStr::new("k4.mmap"), move |file| {
            small_params().0.write_mmap_companion(file)?;
            // Pull the directory out from under the rename: on this
            // platform an open temp file survives, the rename cannot.
            std::fs::remove_dir_all(&cache_dir_for_hook)
        })
    }
    .expect_err("the rename must fail");
    assert_ne!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
    assert!(!cache_dir.join("k4.mmap").exists());
}

#[test]
fn an_interrupted_publication_is_swept_and_a_fresh_one_is_not() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = CompanionCache::from_trusted_dir(unsafe { TrustedParamsDir::new(dir.path()) });
    let prefix = CompanionCache::temp_prefix(std::ffi::OsStr::new(&format!("{NAME}.mmap")));

    // A crashed publisher from long ago: garbage bytes, two hours old.
    let stale = dir.path().join(format!("{prefix}stale"));
    std::fs::write(&stale, b"left behind by a crash").expect("write stale");
    let two_hours_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 60 * 60);
    std::fs::File::options()
        .write(true)
        .open(&stale)
        .expect("open stale")
        .set_times(std::fs::FileTimes::new().set_modified(two_hours_ago))
        .expect("age the stale temp");
    // A publisher that is alive right now: must be left alone.
    let fresh = dir.path().join(format!("{prefix}fresh"));
    std::fs::write(&fresh, b"in progress").expect("write fresh");

    let source = small_params();
    let mapped = cache
        .open_or_build(NAME, || Ok(source.clone()))
        .expect("publication succeeds despite leftovers");
    assert_eq!(digest(&mapped), digest(&source));
    assert!(!stale.exists(), "the stale temp file is swept");
    assert!(
        fresh.exists(),
        "a live publisher's temp file is not touched"
    );
    assert!(cache.published_path(NAME).expect("valid name").exists());
}

#[test]
fn open_or_build_reuses_a_publication_without_building() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = CompanionCache::from_trusted_dir(unsafe { TrustedParamsDir::new(dir.path()) });
    let source = small_params();
    cache
        .open_or_build(NAME, || Ok(source.clone()))
        .expect("first");
    let reused = cache
        .open_or_build(NAME, || {
            panic!("the builder must not run when a companion is published")
        })
        .expect("second");
    assert_eq!(digest(&reused), digest(&source));
}
/// Every name that is not a single ordinary path component is refused,
/// by `published_path`, by `open`, and by publication — before any file
/// system call is made with it. `PathBuf::join` discards the cache root
/// when handed an absolute path and `..` walks out of it, so without this
/// a safe call on a cache could read or create a file anywhere the process
/// can reach.
#[test]
fn a_name_that_is_not_one_component_is_refused_everywhere() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = dir.path().parent().expect("parent").join("escaped.mmap");
    let cache = CompanionCache::from_trusted_dir(unsafe { TrustedParamsDir::new(dir.path()) });

    for name in [
        "../escaped",
        "../../escaped",
        "sub/escaped",
        "..",
        ".",
        "",
        "a\\b",
    ] {
        let err = cache
            .published_path(name)
            .expect_err("published_path must refuse this name");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "name {name:?}");

        // `ParamsProver` is not `Debug`, so these cannot use `expect_err`.
        let err = match cache.open(name) {
            Err(e) => e,
            Ok(_) => panic!("open must refuse the name {name:?}"),
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "name {name:?}");

        let err = match cache.open_or_build(name, || panic!("must not build for {name:?}")) {
            Err(e) => e,
            Ok(_) => panic!("open_or_build must refuse the name {name:?}"),
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "name {name:?}");
    }

    // An absolute name is the other half: `join` would drop the root
    // entirely and hand back the caller's own path.
    let absolute = dir.path().join("absolute.mmap");
    let absolute = absolute.to_str().expect("utf-8");
    assert_eq!(
        cache
            .published_path(absolute)
            .expect_err("absolute name")
            .kind(),
        io::ErrorKind::InvalidInput
    );

    assert!(
        !outside.exists(),
        "nothing may be created outside the cache"
    );
}

/// Publication refuses the same names, through both entry points, and
/// creates nothing when it does.
#[test]
fn publication_refuses_a_name_that_is_not_one_component() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = dir.path().parent().expect("parent").join("escaped.mmap");
    let cache = CompanionCache::from_trusted_dir(unsafe { TrustedParamsDir::new(dir.path()) });

    for name in ["../escaped.mmap", "sub/escaped.mmap", "..", ""] {
        let os = std::ffi::OsStr::new(name);
        // SAFETY: validation rejects the name before invoking the callback.
        let err = unsafe { cache.publish_file(os, |_| panic!("must not write for {name:?}")) }
            .expect_err("publish_file must refuse this name");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "name {name:?}");

        // SAFETY: validation rejects the name before invoking the callback.
        let err = unsafe {
            CompanionCache::publish_into(dir.path(), os, |_| panic!("must not write for {name:?}"))
        }
        .expect_err("publish_into must refuse this name");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "name {name:?}");
    }

    assert!(
        !outside.exists(),
        "nothing may be created outside the cache"
    );
    assert_eq!(
        std::fs::read_dir(dir.path()).expect("read_dir").count(),
        0,
        "a refused publication leaves the directory untouched"
    );
}

/// The property the whole capability exists for: an unwrapped provider
/// does not map a companion even when one is published and readable.
///
/// This is asserted by behaviour rather than by inspection, because the
/// defect it guards against was precisely a safe path reaching a mapping
/// that the types said it should not. `ParamsProver` does not say whether
/// it is mapped, so the test observes the next best thing: the wrapped
/// provider finds the published companion without ever consulting the
/// provider underneath, and the unwrapped one always consults it.
#[test]
fn an_unwrapped_provider_never_reaches_a_published_companion() {
    use futures::executor::block_on;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counting {
        params: ParamsProver,
        calls: AtomicUsize,
    }
    impl ParamsProverProvider for Counting {
        async fn get_params(&self, _k: u8) -> io::Result<ParamsProver> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.params.clone())
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let source = small_params();
    let name = base_crypto::data_provider::MidnightDataProvider::name_k(4);
    let trusted = unsafe { TrustedParamsDir::new(dir.path()) };
    CompanionCache::from_trusted_dir(trusted.clone())
        .open_or_build(&name, || Ok(source.clone()))
        .expect("publish a companion for k=4");
    assert!(
        dir.path().join(format!("{name}.mmap")).exists(),
        "the companion must be on disk for this test to mean anything"
    );

    let bare = Counting {
        params: source.clone(),
        calls: AtomicUsize::new(0),
    };
    let got = block_on(bare.get_params(4)).expect("eager load");
    assert_eq!(digest(&got), digest(&source));
    assert_eq!(
        bare.calls.load(Ordering::SeqCst),
        1,
        "an unwrapped provider must load its own parameters, published \
         companion or not"
    );

    let wrapped = MappedParams::new(
        Counting {
            params: source.clone(),
            calls: AtomicUsize::new(0),
        },
        trusted,
    );
    let got = block_on(wrapped.get_params(4)).expect("mapped load");
    assert_eq!(digest(&got), digest(&source));
    assert_eq!(
        wrapped.inner().calls.load(Ordering::SeqCst),
        0,
        "the wrapped provider must serve from the companion without \
         falling through"
    );
}

#[test]
fn companion_build_is_an_explicit_provider_policy() {
    use futures::executor::block_on;

    struct Counting {
        params: ParamsProver,
        calls: AtomicUsize,
    }
    impl ParamsProverProvider for Counting {
        async fn get_params(&self, _k: u8) -> io::Result<ParamsProver> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(self.params.clone())
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let trusted = unsafe { TrustedParamsDir::new(dir.path()) };
    let name = base_crypto::data_provider::MidnightDataProvider::name_k(4);
    let path = dir.path().join(format!("{name}.mmap"));
    let source = small_params();

    let no_build = MappedParams::new(
        Counting {
            params: source.clone(),
            calls: AtomicUsize::new(0),
        },
        trusted.clone(),
    );
    assert_eq!(
        digest(&block_on(no_build.get_params(4)).expect("fallback")),
        digest(&source)
    );
    assert_eq!(no_build.inner().calls.load(AtomicOrdering::SeqCst), 1);
    assert!(!path.exists(), "default policy must not build a companion");

    let build = MappedParams::with_policy(
        Counting {
            params: source.clone(),
            calls: AtomicUsize::new(0),
        },
        trusted,
        ParamsLoadPolicy {
            build_mmap_companion: true,
            ..ParamsLoadPolicy::default()
        },
    );
    assert_eq!(
        digest(&block_on(build.get_params(4)).expect("publish")),
        digest(&source)
    );
    assert!(path.exists(), "explicit policy publishes a companion");
    assert_eq!(
        digest(&block_on(build.get_params(4)).expect("reopen")),
        digest(&source)
    );
    assert_eq!(
        build.inner().calls.load(AtomicOrdering::SeqCst),
        1,
        "published companion must serve the next load"
    );
}

#[test]
fn companion_miss_preserves_an_explicit_lazy_load_policy() {
    use futures::executor::block_on;

    struct LazyOnly(ParamsProver);
    impl ParamsProverProvider for LazyOnly {
        async fn get_params(&self, _k: u8) -> io::Result<ParamsProver> {
            Err(io::Error::other("process-policy loader was used"))
        }

        async fn get_params_with_policy(
            &self,
            _k: u8,
            policy: ParamsLoadPolicy,
        ) -> io::Result<ParamsProver> {
            if !policy.lazy_params {
                return Err(io::Error::other("explicit lazy policy was lost"));
            }
            Ok(self.0.clone())
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let source = small_params();
    let wrapped = MappedParams::with_policy(
        LazyOnly(source.clone()),
        unsafe { TrustedParamsDir::new(dir.path()) },
        ParamsLoadPolicy {
            lazy_params: true,
            ..ParamsLoadPolicy::default()
        },
    );

    let got = block_on(wrapped.get_params(4)).expect("explicit lazy fallback");
    assert_eq!(digest(&got), digest(&source));
    assert!(
        !dir.path()
            .join(format!(
                "{}.mmap",
                base_crypto::data_provider::MidnightDataProvider::name_k(4)
            ))
            .exists(),
        "a fallback must not publish a companion"
    );
}

#[test]
fn companion_miss_rejects_lazy_load_when_provider_cannot_honor_it() {
    use futures::executor::block_on;

    struct Legacy(ParamsProver);
    impl ParamsProverProvider for Legacy {
        async fn get_params(&self, _k: u8) -> io::Result<ParamsProver> {
            Ok(self.0.clone())
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let wrapped = MappedParams::with_policy(
        Legacy(small_params()),
        unsafe { TrustedParamsDir::new(dir.path()) },
        ParamsLoadPolicy {
            lazy_params: true,
            ..ParamsLoadPolicy::default()
        },
    );

    let error = match block_on(wrapped.get_params(4)) {
        Ok(_) => panic!("unsupported lazy request succeeded"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
}

/// Publishing a known parameter value needs no unsafe capability and never
/// maps a temporary file. This is the path `ParamsProver::write_mmap_companion`
/// takes.
#[test]
fn publish_params_into_is_safe_and_publishes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = small_params();
    let outcome =
        CompanionCache::publish_params_into(dir.path(), std::ffi::OsStr::new("k4.mmap"), &source)
            .expect("publish");
    assert_eq!(outcome, PublishOutcome::Published);
    assert!(dir.path().join("k4.mmap").exists());
}
