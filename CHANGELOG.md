 # Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The changelog starts with version 2.10.0.
Changes to prior versions can be found on the [Github release page](https://github.com/cryptomator/cryptofs/releases).

## [Unreleased](https://github.com/cryptomator/cryptofs/compare/2.9.0...HEAD)

### Added
* [changelog](CHANGELOG.md) file

### Changed
* Use JDK 25 for build (bf26d6c9cd15a2489126ee0409a8ec9eca59da0c)
* Pin external ci actions (#320)

### Fixed
* Replacing internal path class `CryptoPath` with strings in `FilesystemEvent`s (#319)
* Make DOS file attribute class immutable (#305)
