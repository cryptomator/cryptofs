![cryptomator](cryptomator.png)

[![Build Status](https://travis-ci.org/cryptomator/cryptofs.svg?branch=develop)](https://travis-ci.org/cryptomator/cryptofs)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/7248ca7d466843f785f79f33374302c2)](https://www.codacy.com/app/cryptomator/cryptofs)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/7248ca7d466843f785f79f33374302c2)](https://www.codacy.com/app/cryptomator/cryptofs?utm_source=github.com&utm_medium=referral&utm_content=cryptomator/cryptofs&utm_campaign=Badge_Coverage)
[![Known Vulnerabilities](https://snyk.io/test/github/cryptomator/cryptofs/badge.svg)](https://snyk.io/test/github/cryptomator/cryptofs)

**CryptoFS:** Implementation of the [Cryptomator](https://github.com/cryptomator/cryptomator) encryption scheme.

## Features

- Access Cryptomator encrypted vaults from within your Java application
- Uses a `java.nio.file.FileSystem` so code written against the `java.nio.file` API can easily be adapted to work with encrypted data
- Open Source means: No backdoors, control is better than trust

### Security Architecture

For more information on the security details, visit [cryptomator.org](https://cryptomator.org/architecture/).

## Audits

- [Version 1.4.0 audit by Cure53](https://cryptomator.org/audits/2017-11-27%20crypto%20cure53.pdf)

| Finding | Comment |
|---|---|
| 1u1-22-001 | The GPG key is used exclusively for the Maven repositories, is designed for signing only and is protected by a 30-character generated password (alphabet size: 96 chars). It is iterated and salted (SHA1 with 20971520 iterations). An offline attack is also very unattractive. Apart from that, this finding has no influence on the Tresor apps<sup>[1](#footnote-tresor-apps)</sup>. This was not known to Cure53 at the time of reporting. |
| 1u1-22-002 | This issue is related to [siv-mode](https://github.com/cryptomator/siv-mode/). |

## Usage

CryptoFS depends on Java 8 JRE/JDK. In addition, the JCE unlimited strength policy files (needed for 256-bit keys) must be installed.

### Vault Initialization

```java
Path storageLocation = Paths.get("/home/cryptobot/vault");
Files.createDirectories(storageLocation);
CryptoFileSystemProvider.initialize(storageLocation, "masterkey.cryptomator", "password");
```

### Obtaining a FileSystem Instance

You have the option to use the convenience method `CryptoFileSystemProvider#newFileSystem` as follows:  

```java
FileSystem fileSystem = CryptoFileSystemProvider.newFileSystem(
	storageLocation,
	CryptoFileSystemProperties.cryptoFileSystemProperties()
		.withPassphrase("password")
		.withFlags(FileSystemFlags.READONLY) // readonly flag is optional of course
		.build());
```

or to use one of the standard methods from `FileSystems#newFileSystem`:

```java
URI uri = CryptoFileSystemUri.create(storageLocation);
FileSystem fileSystem = FileSystems.newFileSystem(
		uri,
		CryptoFileSystemProperties.cryptoFileSystemProperties()
			.withPassphrase("password")
			.withFlags(FileSystemFlags.READONLY) // readonly flag is optional of course
			.build());
```

**Note:** Instead of `CryptoFileSystemProperties`, you can always pass in a `java.util.Map` with entries set accordingly.

For more details on construction, have a look at the javadoc of `CryptoFileSytemProvider`, `CryptoFileSytemProperties`, and `CryptoFileSytemUris`.

### Using the Constructed FileSystem

```java
try (FileSystem fileSystem = ...) { // see above

	// obtain a path to a test file
	Path testFile = fileSystem.getPath("/foo/bar/test");

	// create all parent directories
	Files.createDirectories(testFile.getParent());

	// Write data to the file
	Files.write(testFile, "test".getBytes());

	// List all files present in a directory
	try (Stream<Path> listing = Files.list(testFile.getParent())) {
		listing.forEach(System.out::println);
	}

}
```

For more details on how to use the constructed `FileSystem`, you may consult the [javadocs of the `java.nio.file` package](http://docs.oracle.com/javase/8/docs/api/java/nio/file/package-summary.html).

## Building

### Dependencies

* Java 8 + JCE unlimited strength policy files (needed for 256-bit keys)
* Maven 3

### Run Maven

```bash
mvn clean install
```

## Contributing to CryptoFS

Please read our [contribution guide](https://github.com/cryptomator/cryptomator/blob/master/CONTRIBUTING.md) if you would like to report a bug, ask a question, or help us with coding.

## Code of Conduct

Help us keep Cryptomator open and inclusive. Please read and follow our [Code of Conduct](https://github.com/cryptomator/cryptomator/blob/master/CODE_OF_CONDUCT.md).

## License

This project is dual-licensed under the AGPLv3 for FOSS projects as well as a commercial license derived from the LGPL for independent software vendors and resellers. If you want to use this library in applications that are *not* licensed under the AGPL, feel free to contact our [sales team](https://cryptomator.org/enterprise/).

---

<sup><a name="footnote-tresor-apps">1</a></sup> The Cure53 pentesting was performed during the development of the apps for 1&1 Mail & Media GmbH.
