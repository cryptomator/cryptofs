/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import com.google.common.collect.ImmutableMap;

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
		Files.walkFileTree(tmpPath, new SimpleFileVisitor<Path>() {

			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
				Files.deleteIfExists(file);
				return FileVisitResult.CONTINUE;
			}

			@Override
			public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
				Files.deleteIfExists(dir);
				return FileVisitResult.CONTINUE;
			}

		});
	}

	@Test
	public void testGetFsViaNioApi() throws IOException {
		URI fsUri = URI.create("cryptomator://" + tmpPath.toString());
		FileSystem fs = FileSystems.newFileSystem(fsUri, ImmutableMap.of(CryptoFileSystemProvider.FS_ENV_PW, "asd"));
		Assert.assertTrue(fs instanceof CryptoFileSystem);
		FileSystem fs2 = FileSystems.getFileSystem(fsUri);
		Assert.assertSame(fs, fs2);
	}

	@Test
	public void testOpenAndCloseFileChannel() throws IOException {
		Path path = Mockito.mock(Path.class);
		CryptoFileSystem fs = Mockito.mock(CryptoFileSystem.class);
		Cryptor cryptor = Mockito.mock(Cryptor.class);
		FileHeaderCryptor headerCryptor = Mockito.mock(FileHeaderCryptor.class);
		CryptoPathMapper pathMapper = Mockito.mock(CryptoPathMapper.class);
		Mockito.when(path.getFileSystem()).thenReturn(fs);
		Mockito.when(fs.getCryptor()).thenReturn(cryptor);
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
		Mockito.when(headerCryptor.create()).thenReturn(Mockito.mock(FileHeader.class));
		Mockito.when(headerCryptor.encryptHeader(Mockito.any())).thenReturn(ByteBuffer.allocate(0));
		Mockito.when(fs.getCryptoPathMapper()).thenReturn(pathMapper);
		Mockito.when(pathMapper.getCiphertextFilePath(Mockito.any())).thenReturn(tmpPath.resolve("foo"));

		try (FileChannel ch = provider.newFileChannel(path, new HashSet<>(Arrays.asList(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW)))) {
			Assert.assertTrue(ch instanceof CryptoFileChannel);
		}
	}

}
