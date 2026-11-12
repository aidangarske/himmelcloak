/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
 * Aidan Garske, Harrison Barrett, and Harman Samra
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! Replace a complete local snapshot without exposing an unfinished write.
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

// Keep the checked directory and private lock open through publication.
pub(crate) struct State {
    directory: File,
    _lock: File,
}

impl State {
    pub fn save(&self, contents: &[u8]) -> io::Result<()> {
        if contents.len() > 64 * 1024 * 1024 {
            return Err(io::Error::other("snapshot is too large"));
        }
        replace_in(&self.directory, |file| file.write_all(contents))
    }

    pub fn lock(directory: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(directory)?;
        let meta = file.metadata()?;
        // SAFETY: geteuid has no preconditions; the production caller requires root.
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe sync directory",
            ));
        }
        // SAFETY: the checked directory descriptor and terminated name are valid.
        let fd = unsafe {
            libc::openat(
                file.as_raw_fd(),
                c".sync.lock".as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is newly opened and ownership passes to File.
        let lock = unsafe { File::from_raw_fd(fd) };
        let lock_meta = lock.metadata()?;
        if !lock_meta.is_file()
            || lock_meta.uid() != meta.uid()
            || lock_meta.mode() & 0o7777 != 0o600
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe sync lock file",
            ));
        }
        // SAFETY: lock owns a live regular-file descriptor.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            directory: file,
            _lock: lock,
        })
    }

    pub fn load(&self) -> io::Result<Option<Vec<u8>>> {
        // SAFETY: the directory descriptor and terminated filename are valid.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                c"users.json".as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error)
            };
        }
        // SAFETY: fd is newly opened and ownership passes to File.
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != self.directory.metadata()?.uid()
            || meta.mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe saved snapshot",
            ));
        }
        const LIMIT: u64 = 64 * 1024 * 1024;
        let mut bytes = Vec::new();
        file.take(LIMIT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > LIMIT {
            return Err(io::Error::other("saved snapshot is too large"));
        }
        Ok(Some(bytes))
    }
}

#[cfg(test)]
fn save(directory: &Path, contents: &[u8]) -> io::Result<()> {
    State::lock(directory)?.save(contents)
}

#[cfg(test)]
fn replace(directory: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    let state = State::lock(directory)?;
    replace_in(&state.directory, write)
}

// Keep preparation separate so permission and flush failures can be injected
// without changing permissions or resource limits for the whole test process.
trait SnapshotFile {
    fn make_readable(&self) -> io::Result<()>;
    fn flush_to_disk(&self) -> io::Result<()>;
}

impl SnapshotFile for File {
    fn make_readable(&self) -> io::Result<()> {
        self.set_permissions(std::fs::Permissions::from_mode(0o644))
    }
    fn flush_to_disk(&self) -> io::Result<()> {
        self.sync_all()
    }
}

fn prepare_file(file: &impl SnapshotFile) -> io::Result<()> {
    file.make_readable()?;
    file.flush_to_disk()
}

fn replace_in(dir: &File, write: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    let temporary = CString::new(format!(
        ".users-{}-{}.tmp",
        std::process::id(),
        NEXT_FILE.fetch_add(1, Ordering::Relaxed)
    ))
    .unwrap();
    // Anchor every operation to the checked directory descriptor. create_new
    // semantics reject an existing temporary file, including a symlink.
    // SAFETY: the descriptor is live and the name is a terminated CString.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor owned by this File.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let result = (|| {
        write(&mut file)?;
        prepare_file(&file)?;
        let destination = c"users.json";
        // SAFETY: both names are terminated and the directory descriptor is live.
        if unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                temporary.as_ptr(),
                dir.as_raw_fd(),
                destination.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // If this fails, the complete new file is visible but its survival across
        // a power loss is uncertain. Do not roll back a completed rename.
        dir.sync_all()
    })();
    // SAFETY: removes only our temporary name in the checked directory. After a
    // successful rename that name is absent; the destination is never removed.
    unsafe {
        libc::unlinkat(dir.as_raw_fd(), temporary.as_ptr(), 0);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink, path::PathBuf};

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "himmelcloak-snapshot-{}-{}",
                std::process::id(),
                NEXT_FILE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn save_stays_in_the_locked_directory_if_its_path_is_replaced() {
        let parent = Directory::new();
        let original = parent.0.join("state");
        let moved = parent.0.join("moved");
        fs::create_dir(&original).unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
        let state = State::lock(&original).unwrap();
        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();
        state.save(b"snapshot").unwrap();
        assert_eq!(fs::read(moved.join("users.json")).unwrap(), b"snapshot");
        assert!(!original.join("users.json").exists());
    }

    #[test]
    fn locks_serialize_syncs_and_saved_state_rejects_symlinks() {
        let dir = Directory::new();
        let state = State::lock(&dir.0).unwrap();
        assert!(State::lock(&dir.0).is_err());
        assert!(state.load().unwrap().is_none());
        state.save(b"saved").unwrap();
        assert_eq!(state.load().unwrap().unwrap(), b"saved");
        fs::remove_file(dir.0.join("users.json")).unwrap();
        symlink("missing", dir.0.join("users.json")).unwrap();
        assert!(state.load().is_err());
        drop(state);
        assert!(State::lock(&dir.0).is_ok());
    }

    #[test]
    fn sync_lock_is_private_even_when_the_directory_is_public() {
        use std::{os::unix::process::CommandExt, process::Command};

        let dir = Directory::new();
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        let state = State::lock(&dir.0).unwrap();
        let path = dir.0.join(".sync.lock");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        drop(state);
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            let status = Command::new("sh")
                .args([
                    "-c",
                    "test -x \"$1\" && test ! -r \"$2\" && test ! -w \"$2\"",
                    "sh",
                ])
                .arg(&dir.0)
                .arg(&path)
                .gid(65534)
                .uid(65534)
                .status()
                .unwrap();
            assert!(status.success());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(State::lock(&dir.0).is_err());
        fs::remove_file(&path).unwrap();
        symlink("missing", &path).unwrap();
        assert!(State::lock(&dir.0).is_err());
    }

    #[test]
    fn publishes_a_complete_readable_snapshot() {
        let dir = Directory::new();
        save(&dir.0, b"old").unwrap();
        save(&dir.0, b"new complete snapshot").unwrap();
        let path = dir.0.join("users.json");
        assert_eq!(fs::read(&path).unwrap(), b"new complete snapshot");
        assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o644);
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 2);
    }

    #[test]
    fn failed_write_keeps_last_good_snapshot_and_removes_temporary_file() {
        let dir = Directory::new();
        save(&dir.0, b"last good snapshot").unwrap();
        let result = replace(&dir.0, |file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("injected write failure"))
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read(dir.0.join("users.json")).unwrap(),
            b"last good snapshot"
        );
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 2);
    }

    #[test]
    fn rejects_writable_or_symlinked_directories() {
        let dir = Directory::new();
        let link = dir.0.join("link");
        symlink(&dir.0, &link).unwrap();
        assert!(save(&link, b"data").is_err());
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(save(&dir.0, b"data").is_err());
    }

    #[test]
    fn destination_symlink_cannot_overwrite_another_file() {
        let dir = Directory::new();
        let outside = dir.0.join("other");
        fs::write(&outside, b"untouched").unwrap();
        symlink(&outside, dir.0.join("users.json")).unwrap();
        save(&dir.0, b"snapshot").unwrap();
        assert_eq!(fs::read(outside).unwrap(), b"untouched");
        assert!(!fs::symlink_metadata(dir.0.join("users.json"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn oversized_and_writable_saved_files_are_rejected() {
        let dir = Directory::new();
        let state = State::lock(&dir.0).unwrap();
        let path = dir.0.join("users.json");
        fs::write(&path, b"last good").unwrap();
        assert!(state.save(&vec![0; 64 * 1024 * 1024 + 1]).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"last good");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(state.load().is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(64 * 1024 * 1024 + 1)
            .unwrap();
        assert!(state.load().is_err());
    }

    #[test]
    fn failed_open_and_rename_do_not_remove_existing_data() {
        let dir = Directory::new();
        let sentinel = dir.0.join("sentinel");
        fs::write(&sentinel, b"unchanged").unwrap();
        let ordinary_file = File::open(&sentinel).unwrap();
        assert!(replace_in(&ordinary_file, File::flush).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"unchanged");
        let destination = dir.0.join("users.json");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("keep"), b"old data").unwrap();
        assert!(save(&dir.0, b"new data").is_err());
        assert_eq!(fs::read(destination.join("keep")).unwrap(), b"old data");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 3);
        assert!(replace(&dir.0.join("missing"), File::flush).is_err());
    }

    #[test]
    fn permission_and_flush_failures_preserve_the_old_snapshot() {
        struct Fault<'a> {
            file: &'a File,
            fail_permissions: bool,
        }
        impl SnapshotFile for Fault<'_> {
            fn make_readable(&self) -> io::Result<()> {
                if self.fail_permissions {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "injected permission failure",
                    ))
                } else {
                    self.file.make_readable()
                }
            }
            fn flush_to_disk(&self) -> io::Result<()> {
                Err(io::Error::other("injected flush failure"))
            }
        }
        let dir = Directory::new();
        save(&dir.0, b"last good snapshot").unwrap();
        for fail_permissions in [true, false] {
            let error = replace(&dir.0, |file| {
                file.write_all(b"new snapshot")?;
                prepare_file(&Fault {
                    file,
                    fail_permissions,
                })
            })
            .unwrap_err();
            assert_eq!(
                error.kind(),
                if fail_permissions {
                    io::ErrorKind::PermissionDenied
                } else {
                    io::ErrorKind::Other
                }
            );
            assert_eq!(
                fs::read(dir.0.join("users.json")).unwrap(),
                b"last good snapshot"
            );
            assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 2);
        }
    }

    #[test]
    fn flush_only_writer_can_complete_publication() {
        let dir = Directory::new();
        replace(&dir.0, File::flush).unwrap();
        assert!(fs::read(dir.0.join("users.json")).unwrap().is_empty());
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 2);
    }
}
