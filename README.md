![cryptomator](cryptomator.png)

[![Build Status](https://travis-ci.org/cryptomator/cryptofs.svg?branch=develop)](https://travis-ci.org/cryptomator/cryptofs)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/7248ca7d466843f785f79f33374302c2)](https://www.codacy.com/app/cryptomator/cryptofs)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/7248ca7d466843f785f79f33374302c2)](https://www.codacy.com/app/cryptomator/cryptofs?utm_source=github.com&utm_medium=referral&utm_content=cryptomator/cryptofs&utm_campaign=Badge_Coverage)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/10006/badge.svg)](https://scan.coverity.com/projects/cryptomator-cryptofs)

**CryptoFS** - Implementation of the [Cryptomator](https://github.com/cryptomator/cryptomator) encryption scheme.

## Disclaimer

This project is in an early stage and not ready for production use. We recommend to use it only for testing and evaluation purposes.

## Features

- Access Cryptomator encrypted vaults from within your Java application
- Uses a ``java.nio.file.FileSystem`` so code written against the java.nio.file API can easily be adapted to work with encrypted data
- Open Source means: No backdoors, control is better than trust

### Security Architecture

For more information on the security details visit [cryptomator.org](https://cryptomator.org/architecture/).

## Usage

CryptoFS depends on a Java 8 JRE/JDK. In addition the JCE unlimited strength policy files (needed for 256-bit keys) must be installed.

### Construction

You have the option to use the convenience method ``CryptoFileSystemProvider#newFileSystem`` as follows:  

```java
Path storageLocation = Paths.get("/home/cryptobot/vault");
FileSystem fileSystem = CryptoFileSystemProvider.newFileSystem(
	storageLocation,
	CryptoFileSystemProperties.cryptoFileSystemProperties()
		.withPassphrase("password")
		.withReadonlyFlag() // readonly flag is optional of course
		.build());
```

or to use one of the standard methods from ``FileSystems#newFileSystem``:

```java
Path storageLocation = Paths.get("/home/cryptobot/vault");
URI uri = CryptoFileSystemUri.create(storageLocation);
FileSystem fileSystem = FileSystems.newFileSystem(
		uri,
		CryptoFileSystemProperties.cryptoFileSystemProperties()
			.withPassphrase("password")
			.withReadonlyFlag() // readonly flag is optional of course
			.build());
```

**Note** - Instead of CryptoFileSystemProperties you can always pass in a ``java.util.Map`` with entries set accordingly.

For more details on construction have a look at the javadoc of ``CryptoFileSytemProvider``, ``CryptoFileSytemProperties`` and ``CryptoFileSytemUris``.

### Using the constructed file system

```java
FileSystem fileSystem = ...; // see above

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
```

For more details on how to use the constructed file system you may consult the [javadocs of the java.nio.file package](http://docs.oracle.com/javase/8/docs/api/java/nio/file/package-summary.html).

## Building

### Dependencies

* Java 8 + JCE unlimited strength policy files (needed for 256-bit keys)
* Maven 3

### Run Maven

```bash
mvn clean install
```

## Contributing to CryptoFS

Please read our [contribution guide](https://github.com/cryptomator/cryptomator/blob/master/CONTRIBUTING.md), if you would like to report a bug, ask a question or help us with coding.

## Code of Conduct

Help us keep Cryptomator open and inclusive. Please read and follow our [Code of Conduct](https://github.com/cryptomator/cryptomator/blob/master/CODE_OF_CONDUCT.md).

## License

Distributed under the AGPLv3. See the `LICENSE.txt` file for more info.
