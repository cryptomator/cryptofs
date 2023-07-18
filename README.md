![cryptomator](cryptomator.png)

[![Build](https://github.com/cryptomator/cryptofs/workflows/Build/badge.svg)](https://github.com/cryptomator/cryptofs/actions?query=workflow%3ABuild)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=cryptomator_cryptofs&metric=alert_status)](https://sonarcloud.io/dashboard?id=cryptomator_cryptofs)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=cryptomator_cryptofs&metric=coverage)](https://sonarcloud.io/dashboard?id=cryptomator_cryptofs)
[![Known Vulnerabilities](https://snyk.io/test/github/cryptomator/cryptofs/badge.svg)](https://snyk.io/test/github/cryptomator/cryptofs)

**CryptoFS:** Implementation of the [Cryptomator](https://github.com/cryptomator/cryptomator) encryption scheme.

## Features

- Access Cryptomator encrypted vaults from within your Java application
- Uses a `java.nio.file.FileSystem` so code written against the `java.nio.file` API can easily be adapted to work with encrypted data
- Open Source means: No backdoors, control is better than trust

### Security Architecture

For more information on the security details, visit [docs.cryptomator.org](https://docs.cryptomator.org/en/latest/security/architecture/).

## Audits

- [Version 1.4.0 audit by Cure53](https://cryptomator.org/audits/2017-11-27%20crypto%20cure53.pdf)

| Finding | Comment |
|---|---|
| 1u1-22-001 | The GPG key is used exclusively for the Maven repositories, is designed for signing only and is protected by a 30-character generated password (alphabet size: 96 chars). It is iterated and salted (SHA1 with 20971520 iterations). An offline attack is also very unattractive. Apart from that, this finding has no influence on the Tresor apps<sup>[1](#footnote-tresor-apps)</sup>. This was not known to Cure53 at the time of reporting. |
| 1u1-22-002 | This issue is related to [siv-mode](https://github.com/cryptomator/siv-mode/). |

## Usage

### Vault Initialization

```java
Path storageLocation = Paths.get("/home/cryptobot/vault");
Files.createDirectories(storageLocation);
Masterkey masterkey = Masterkey.generate(csprng));
MasterkeyLoader loader = ignoredUri -> masterkey.copy(); //create a copy because the key handed over to init() method will be destroyed
CryptoFileSystemProperties fsProps = CryptoFileSystemProperties.cryptoFileSystemProperties().withKeyLoader(loader).build();
CryptoFileSystemProvider.initialize(storageLocation, fsProps, "myKeyId");
```

The key material used for initialization and later de- & encryption is given by the [org.cryptomator.cryptolib.api.Masterkeyloader](https://github.com/cryptomator/cryptolib/blob/2.1.2/src/main/java/org/cryptomator/cryptolib/api/MasterkeyLoader.java) interface.

### Obtaining a FileSystem Instance

You have the option to use the convenience method `CryptoFileSystemProvider#newFileSystem` as follows:  

```java
FileSystem fileSystem = CryptoFileSystemProvider.newFileSystem(
	storageLocation,
	CryptoFileSystemProperties.cryptoFileSystemProperties()
		.withKeyLoader(ignoredUri -> masterkey.copy())
		.withFlags(FileSystemFlags.READONLY) // readonly flag is optional of course
		.build());
```

or to use one of the standard methods from `FileSystems#newFileSystem`:

```java
URI uri = CryptoFileSystemUri.create(storageLocation);
FileSystem fileSystem = FileSystems.newFileSystem(
		uri,
		CryptoFileSystemProperties.cryptoFileSystemProperties()
            .withKeyLoader(ignoredUri -> masterkey.copy())
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

For more details on how to use the constructed `FileSystem`, you may consult the [javadocs of the `java.nio.file` package](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/nio/file/package-summary.html).

## Building

### Dependencies

* Java 17
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
