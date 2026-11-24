 # Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The changelog starts with version 2.10.0.
Changes to prior versions can be found on the [GitHub release page](https://github.com/cryptomator/cryptofs/releases).

## [Unreleased](https://github.com/cryptomator/cryptofs/compare/2.12.1...HEAD)

### Added
* `FileWriteConflictEvent`, emitted once when a write or save through an open file is refused, because its ciphertext changed outside of this file system while the file was open ([#381](https://github.com/cryptomator/cryptofs/issues/381), [#385](https://github.com/cryptomator/cryptofs/pull/385))

### Changed
* `DecryptionFailedEvent` for an undecryptable chunk is now delivered on its own thread and always names the file ([#385](https://github.com/cryptomator/cryptofs/pull/385))

### Fixed
* Fixed an open file putting data it buffered before a sync client or another device changed its ciphertext in place over the new version, which could also leave chunks undecryptable: the write, force, close or truncate that finds the change now fails with an I/O error, and the open file saves nothing more until it is reopened ([#381](https://github.com/cryptomator/cryptofs/issues/381), [#385](https://github.com/cryptomator/cryptofs/pull/385))
* Fixed a write past the end of a file that was shortened outside of this file system while it was open encrypting leftover bytes of another file into it. Such a write now fails as a conflict ([#382](https://github.com/cryptomator/cryptofs/issues/382), [#385](https://github.com/cryptomator/cryptofs/pull/385))
* Fixed a read past the end of a file that was shortened outside of this file system while it was open hanging or throwing `IllegalArgumentException`. It now ends at the new end of the file ([#382](https://github.com/cryptomator/cryptofs/issues/382), [#385](https://github.com/cryptomator/cryptofs/pull/385))
* Fixed closing a channel setting the last-modified time of a file that was changed in place outside of this file system back to an older time ([#383](https://github.com/cryptomator/cryptofs/issues/383), [#385](https://github.com/cryptomator/cryptofs/pull/385))
* Fixed copying a file to another vault hanging when the source got shorter during the copy. The copy now fails with an I/O error ([#384](https://github.com/cryptomator/cryptofs/issues/384), [#385](https://github.com/cryptomator/cryptofs/pull/385))
* Fixed `transferFrom` and `transferTo` of a file channel hanging when the other channel is non-blocking and has no bytes ready or no room left. They now return the number of bytes transferred so far ([#385](https://github.com/cryptomator/cryptofs/pull/385))
* Fixed `transferFrom` of a file channel taking up to 4 KiB more from the source channel than it wrote to the file ([#385](https://github.com/cryptomator/cryptofs/pull/385))


## [2.12.1](https://github.com/cryptomator/cryptofs/releases/tag/2.12.1) - 2026-11-23

### Fixed
* Fixed long-named items that the orphaned directory health check recovers into `LOST+FOUND` being unreadable in vaults with certain shortening thresholds, when the original directory ID was lost ([#375](https://github.com/cryptomator/cryptofs/issues/375), [#376](https://github.com/cryptomator/cryptofs/pull/376))
* Fixed a file that a sync client replaced while it was open getting corrupted by channels opened afterwards, which still used the replaced file's header ([#377](https://github.com/cryptomator/cryptofs/issues/377), [#380](https://github.com/cryptomator/cryptofs/pull/380))
* Fixed closing a channel overwriting the last-modified time of a file that a sync client replaced in the meantime, on file systems that report file keys ([#377](https://github.com/cryptomator/cryptofs/issues/377), [#380](https://github.com/cryptomator/cryptofs/pull/380))
* Fixed a file created at the path of a file still open with `DELETE_ON_CLOSE` getting mixed up with the deleted file instead of being a new file ([#379](https://github.com/cryptomator/cryptofs/issues/379), [#380](https://github.com/cryptomator/cryptofs/pull/380))
* Fixed closing a file deleting the Files-in-Use marker that another device had written over this device's marker ([#377](https://github.com/cryptomator/cryptofs/issues/377), [#380](https://github.com/cryptomator/cryptofs/pull/380))
* Fixed a read near the end of a file returning no bytes when the destination buffer's position was not zero, which could make `Files.readAllBytes` fail with `OutOfMemoryError` ([#378](https://github.com/cryptomator/cryptofs/issues/378), [#380](https://github.com/cryptomator/cryptofs/pull/380))
* Fixed a partial write of a file header going unnoticed and leaving a torn, undecryptable header on disk ([#380](https://github.com/cryptomator/cryptofs/pull/380))
* Fixed a file possibly getting corrupted when it was opened at the same moment its last open channel was closed ([#380](https://github.com/cryptomator/cryptofs/pull/380))


## [2.12.0](https://github.com/cryptomator/cryptofs/releases/tag/2.12.0) - 2026-11-11

### Changed
* Moving a file with `REPLACE_EXISTING` onto a file that is currently open now replaces it like a POSIX rename, instead of failing with `FileAlreadyExistsException`: channels of the replaced file keep reading its old content, while the path shows the moved file ([#374](https://github.com/cryptomator/cryptofs/pull/374))
* `DecryptionFailedEvent` for an undecryptable file header is now delivered once internal locks are released, so event consumers may access the filesystem ([#374](https://github.com/cryptomator/cryptofs/pull/374))
* Improved write performance by encrypting chunks from a writable buffer, which allows the JCE fast path for AES-GCM ([#370](https://github.com/cryptomator/cryptofs/pull/370))

### Fixed
* Fixed files with long (shortened) names becoming undecryptable when moved while open, or when replacing an open file ([#374](https://github.com/cryptomator/cryptofs/pull/374))
* Fixed an open file keeping its old content at its path after `Files.copy` with `REPLACE_EXISTING` or a symlink replaced it ([#374](https://github.com/cryptomator/cryptofs/pull/374))
* Fixed a partial write of an encrypted chunk going unnoticed and leaving a torn chunk on disk ([#370](https://github.com/cryptomator/cryptofs/pull/370))


## [2.11.1](https://github.com/cryptomator/cryptofs/releases/tag/2.11.1) - 2026-10-26

### Changed
* Updated dependencies:
  * `org.cryptomator:cryptolib` from 2.3.0 to 2.4.0
  * `com.auth0:java-jwt` from 4.6.1 to 4.6.2
  * `com.github.ben-manes.caffeine:caffeine` from 3.3.0 to 3.3.1

### Fixed
* Fixed a broken directory link file (e.g. an empty `dir.c9r`) blocking all further directory listings and preventing the filesystem from closing ([#365](https://github.com/cryptomator/cryptofs/issues/365))


## [2.11.0](https://github.com/cryptomator/cryptofs/releases/tag/2.11.0) - 2026-10-14

### Added
* `VaultConfig.UnverifiedVaultConfig.allegedVaultId()` to read the vault id from an unverified vault config (fc29aabb411668c8cabc59491dabc73183e1e00c)

### Changed
* Updated dependencies ([#357](https://github.com/cryptomator/cryptofs/pull/357), [#359](https://github.com/cryptomator/cryptofs/pull/359)):
  * `com.auth0:java-jwt` from 4.5.1 to 4.6.1
  * `com.github.ben-manes.caffeine:caffeine` from 3.2.3 to 3.3.0
  * `org.slf4j:slf4j-api` from 2.0.17 to 2.0.20

### Fixed
* Fixed automatic conflict resolution could create duplicate directory link with an already existing directory id ([#355](https://github.com/cryptomator/cryptofs/issues/355))
* Fixed Module descriptor declared `javax.inject` as `requires static`, although it is required at runtime (ea3a9ca3687e432cde0159cd408e775d181625fd)


## [2.10.0](https://github.com/cryptomator/cryptofs/releases/tag/2.10.0) - 2026-03-05

### Added
* Files-in-Use: Optional feature to indicate for external parties if an encrypted file is currently opened by this filesystem ([#312](https://github.com/cryptomator/cryptofs/pull/312), [#338](https://github.com/cryptomator/cryptofs/pull/338))
* Changelog file

### Changed
* Use JDK 25 for build (bf26d6c9cd15a2489126ee0409a8ec9eca59da0c)
* Pin external ci actions ([#320](https://github.com/cryptomator/cryptofs/pull/320))
* Use Maven wrapper ([#341](https://github.com/cryptomator/cryptofs/pull/341))
* Updated dependencies:
  * `com.github.ben-manes.caffeine:caffeine` from 3.2.0 to 3.2.3 ([#323](https://github.com/cryptomator/cryptofs/pull/323))
  * `org.cryptomator:cryptolib` from 2.2.1 to 2.2.2
  * `com.auth0:java-jwt` from 4.5.0 to 4.5.1
* Removed dependencies:
  * `com.google.guava:guava`

### Fixed
* Replacing internal path class `CryptoPath` with strings in `FilesystemEvent`s ([#319](https://github.com/cryptomator/cryptofs/pull/319))
* Make DOS file attribute class immutable ([#305](https://github.com/cryptomator/cryptofs/pull/305))
