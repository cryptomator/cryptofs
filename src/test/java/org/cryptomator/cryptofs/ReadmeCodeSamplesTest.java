package org.cryptomator.cryptofs;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class ReadmeCodeSamplesTest {

	private Path storageLocation;

	@Before
	public void setup() throws IOException {
		storageLocation = Files.createTempDirectory("unit-tests");
	}

	@After
	public void teardown() throws IOException {
		Files.walkFileTree(storageLocation, new DeletingFileVisitor());
	}

	@Test
	public void testReadmeCodeSampleUsingFileSystemConstructionMethodA() throws IOException {
		FileSystem fileSystem = CryptoFileSystemProvider.newFileSystem(storageLocation, CryptoFileSystemProperties.cryptoFileSystemProperties().withPassphrase("password").build());

		runCodeSample(fileSystem);
	}

	@Test
	public void testReadmeCodeSampleUsingFileSystemConstructionMethodB() throws IOException {
		URI uri = CryptoFileSystemUris.createUri(storageLocation);
		FileSystem fileSystem = FileSystems.newFileSystem(uri, CryptoFileSystemProperties.cryptoFileSystemProperties().withPassphrase("password").build());

		runCodeSample(fileSystem);
	}

	private void runCodeSample(FileSystem fileSystem) throws IOException {
		// obtain a path to a test file
		Path testFile = fileSystem.getPath("/foo/bar/test");

		// create all parent directories
		Files.createDirectories(testFile.getParent());

		// Write data to the file
		Files.write(testFile, "test".getBytes());

		// List all files present in a directory
		List<Path> files = new ArrayList<>();
		Files.list(testFile.getParent()).forEach(files::add);

		assertEquals(1, files.size());
		assertEquals("/foo/bar/test", files.get(0).toString());
		assertEquals(Files.size(testFile), 4);
	}

}
