/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.nio.file.Files.readAllBytes;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.apache.commons.lang3.SystemUtils.IS_OS_WINDOWS;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.EnumSet;

import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

public class CryptoFileSystemProviderIntegrationTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private Path tmpPath;

	@Before
	public void setup() throws IOException {
		tmpPath = Files.createTempDirectory("unit-tests");
	}

	@After
	public void teardown() throws IOException {
		Files.walkFileTree(tmpPath, new DeletingFileVisitor());
	}

	@Test
	public void testGetFsViaNioApi() throws IOException {
		URI fsUri = CryptoFileSystemUri.create(tmpPath);
		FileSystem fs = FileSystems.newFileSystem(fsUri, cryptoFileSystemProperties().withPassphrase("asd").build());
		Assert.assertTrue(fs instanceof CryptoFileSystemImpl);
		Assert.assertTrue(Files.exists(tmpPath.resolve("masterkey.cryptomator")));
		FileSystem fs2 = FileSystems.getFileSystem(fsUri);
		Assert.assertSame(fs, fs2);
	}

	@Test
	public void testInitAndOpenFsWithPepper() throws IOException {
		FileSystem fs = Jimfs.newFileSystem(Configuration.unix());
		Path pathToVault = fs.getPath("/vaultDir");
		Path masterkeyFile = pathToVault.resolve("masterkey.cryptomator");
		Path dataDir = pathToVault.resolve("d");
		byte[] pepper = "pepper".getBytes(StandardCharsets.US_ASCII);

		// Initialize vault:
		Files.createDirectory(pathToVault);
		CryptoFileSystemProvider.initialize(pathToVault, "masterkey.cryptomator", pepper, "asd");
		Assert.assertTrue(Files.isDirectory(dataDir));
		Assert.assertTrue(Files.isRegularFile(masterkeyFile));

		// Attempt 1: Correct pepper:
		CryptoFileSystemProperties properties = cryptoFileSystemProperties() //
				.withFlags() //
				.withMasterkeyFilename("masterkey.cryptomator") //
				.withPassphrase("asd") //
				.withPepper(pepper) //
				.build();
		try (CryptoFileSystem cryptoFs = CryptoFileSystemProvider.newFileSystem(pathToVault, properties)) {
			Assert.assertNotNull(cryptoFs);
		}

		// Attempt 2: Invalid pepper resulting in InvalidPassphraseException:
		CryptoFileSystemProperties wrongProperties = cryptoFileSystemProperties() //
				.withFlags() //
				.withMasterkeyFilename("masterkey.cryptomator") //
				.withPassphrase("asd") //
				.build();
		thrown.expect(InvalidPassphraseException.class);
		CryptoFileSystemProvider.newFileSystem(pathToVault, wrongProperties);
	}

	@Test
	public void testOpenAndCloseFileChannel() throws IOException {
		FileSystem fs = CryptoFileSystemProvider.newFileSystem(tmpPath, cryptoFileSystemProperties().withPassphrase("asd").build());
		try (FileChannel ch = FileChannel.open(fs.getPath("/foo"), EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW))) {
			Assert.assertTrue(ch instanceof CryptoFileChannel);
		}
	}

	@Test
	public void testCopyFileFromOneCryptoFileSystemToAnother() throws IOException {
		byte[] data = new byte[] { 1, 2, 3, 4, 5, 6, 7 };

		Path fs1Location = tmpPath.resolve("foo");
		Path fs2Location = tmpPath.resolve("bar");
		Files.createDirectories(fs1Location);
		Files.createDirectories(fs2Location);
		FileSystem fs1 = CryptoFileSystemProvider.newFileSystem(fs1Location, cryptoFileSystemProperties().withPassphrase("asd").build());
		FileSystem fs2 = CryptoFileSystemProvider.newFileSystem(fs2Location, cryptoFileSystemProperties().withPassphrase("qwe").build());
		Path file1 = fs1.getPath("/foo/bar");
		Path file2 = fs2.getPath("/bar/baz");
		Files.createDirectories(file1.getParent());
		Files.createDirectories(file2.getParent());
		Files.write(file1, data);

		Files.copy(file1, file2);

		assertThat(readAllBytes(file1), is(data));
		assertThat(readAllBytes(file2), is(data));
	}

	@Test
	public void testCopyFileByRelacingExistingFromOneCryptoFileSystemToAnother() throws IOException {
		byte[] data = new byte[] { 1, 2, 3, 4, 5, 6, 7 };
		byte[] data2 = new byte[] { 10, 11, 12 };

		Path fs1Location = tmpPath.resolve("foo");
		Path fs2Location = tmpPath.resolve("bar");
		Files.createDirectories(fs1Location);
		Files.createDirectories(fs2Location);
		FileSystem fs1 = CryptoFileSystemProvider.newFileSystem(fs1Location, cryptoFileSystemProperties().withPassphrase("asd").build());
		FileSystem fs2 = CryptoFileSystemProvider.newFileSystem(fs2Location, cryptoFileSystemProperties().withPassphrase("qwe").build());
		Path file1 = fs1.getPath("/foo/bar");
		Path file2 = fs2.getPath("/bar/baz");
		Files.createDirectories(file1.getParent());
		Files.createDirectories(file2.getParent());
		Files.write(file1, data);
		Files.write(file2, data2);

		Files.copy(file1, file2, REPLACE_EXISTING);

		assertThat(readAllBytes(file1), is(data));
		assertThat(readAllBytes(file2), is(data));
	}

	@Test
	public void testMoveFileFromOneCryptoFileSystemToAnother() throws IOException {
		byte[] data = new byte[] { 1, 2, 3, 4, 5, 6, 7 };

		Path fs1Location = tmpPath.resolve("foo");
		Path fs2Location = tmpPath.resolve("bar");
		Files.createDirectories(fs1Location);
		Files.createDirectories(fs2Location);
		FileSystem fs1 = CryptoFileSystemProvider.newFileSystem(fs1Location, cryptoFileSystemProperties().withPassphrase("asd").build());
		FileSystem fs2 = CryptoFileSystemProvider.newFileSystem(fs2Location, cryptoFileSystemProperties().withPassphrase("qwe").build());
		Path file1 = fs1.getPath("/foo/bar");
		Path file2 = fs2.getPath("/bar/baz");
		Files.createDirectories(file1.getParent());
		Files.createDirectories(file2.getParent());
		Files.write(file1, data);

		Files.move(file1, file2);

		assertThat(Files.exists(file1), is(false));
		assertThat(readAllBytes(file2), is(data));
	}

	@Test
	public void testDosFileAttributes() throws IOException {
		Assume.assumeTrue(IS_OS_WINDOWS);

		FileSystem fs = CryptoFileSystemProvider.newFileSystem(tmpPath, cryptoFileSystemProperties().withPassphrase("asd").build());
		Path file = fs.getPath("/test");
		Files.write(file, new byte[1]);

		Files.setAttribute(file, "dos:hidden", true);
		Files.setAttribute(file, "dos:system", true);
		Files.setAttribute(file, "dos:archive", true);
		Files.setAttribute(file, "dos:readOnly", true);

		assertThat(Files.getAttribute(file, "dos:hidden"), is(true));
		assertThat(Files.getAttribute(file, "dos:system"), is(true));
		assertThat(Files.getAttribute(file, "dos:archive"), is(true));
		assertThat(Files.getAttribute(file, "dos:readOnly"), is(true));
	}

}
