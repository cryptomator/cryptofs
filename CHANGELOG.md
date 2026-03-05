 # Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The changelog starts with version 2.10.0.
Changes to prior versions can be found on the [GitHub release page](https://github.com/cryptomator/cryptofs/releases).

## [Unreleased](https://github.com/cryptomator/cryptofs/compare/2.9.0...HEAD)

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

### Fixed
* Replacing internal path class `CryptoPath` with strings in `FilesystemEvent`s ([#319](https://github.com/cryptomator/cryptofs/pull/319))
* Make DOS file attribute class immutable ([#305](https://github.com/cryptomator/cryptofs/pull/305))
