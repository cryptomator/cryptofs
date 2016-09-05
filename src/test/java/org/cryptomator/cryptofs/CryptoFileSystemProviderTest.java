/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.EnumSet;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class CryptoFileSystemProviderTest {

	private static final SecureRandom NULL_RANDOM = new SecureRandom() {
		@Override
		public synchronized void nextBytes(byte[] bytes) {
			Arrays.fill(bytes, (byte) 0x00);
		};
	};

	private Path tmpPath;
	private CryptoFileSystemProvider provider;

	@Before
	public void setup() throws IOException {
		tmpPath = Files.createTempDirectory("unit-tests");
		provider = new CryptoFileSystemProvider(NULL_RANDOM);
	}

	@After
	public void teardown() throws IOException {
		Files.walkFileTree(tmpPath, new DeletingFileVisitor());
	}

	@Test
	public void testGetFsViaNioApi() throws IOException {
		URI fsUri = CryptoFileSystemUris.createUri(tmpPath);
		FileSystem fs = FileSystems.newFileSystem(fsUri, cryptoFileSystemProperties().withPassphrase("asd").build());
		Assert.assertTrue(fs instanceof CryptoFileSystem);
		Assert.assertTrue(Files.exists(tmpPath.resolve("masterkey.cryptomator")));
		FileSystem fs2 = FileSystems.getFileSystem(fsUri);
		Assert.assertSame(fs, fs2);
	}

	@Test
	public void testOpenAndCloseFileChannel() throws IOException {
		FileSystem fs = CryptoFileSystemProvider.newFileSystem(tmpPath, cryptoFileSystemProperties().withPassphrase("asd").build());
		try (FileChannel ch = provider.newFileChannel(fs.getPath("/foo"), EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW))) {
			Assert.assertTrue(ch instanceof CryptoFileChannel);
		}
	}

}
