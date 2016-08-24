![cryptomator](cryptomator.png)

**CryptoFS** - Implementation of the [Cryptomator](https://github.com/cryptomator/cryptomator) encryption scheme.

## Disclaimer

This project is in an early stage and not ready for production use. We recommend to use it only for testing and evaluation purposes.

## Features

- Access Cryptomator encrypted vaults from without your Java application
- Uses a ``java.nio.file.FileSystem`` so code written against the java.nio.file API can easily be adapted to work with encrypted data 
- Open Source means: No backdoors, control is better than trust

### Security Architecture

For more information on the security details visit [cryptomator.org](https://cryptomator.org/architecture/).

## Usage

### Construction

You have the option to use the convenience method ``CryptoFileSystemProvider#newFileSystem`` as follows:  

```
Path storageLocation = Paths.get("/home/cryptobot/vault");
FileSystem fileSystem = CryptoFileSystemProvider.newFileSystem(
	storageLocation,
	CryptoFileSystemProperties.cryptoFileSystemProperties()
		.withPassphrase("password")
		.withReadonlyFlag() // readonly flag is optional of course
		.build());
```

or to use on of the standard methods from ``FileSystems#newFileSystem``:

```
Path storageLocation = Paths.get("/home/cryptobot/vault");
URI uri = CryptoFileSystemUris.createUri(storageLocation);
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

```
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

```
mvn clean install
```

## Contributing to CryptoFS

Please read our [contribution guide](https://github.com/cryptomator/cryptomator/blob/master/CONTRIBUTING.md), if you would like to report a bug, ask a question or help us with coding.

## Code of Conduct

Help us keep Cryptomator open and inclusive. Please read and follow our [Code of Conduct](https://github.com/cryptomator/cryptomator/blob/master/CODE_OF_CONDUCT.md).

## License

Distributed under the GPLv3. See the `LICENSE.txt` file for more info.
