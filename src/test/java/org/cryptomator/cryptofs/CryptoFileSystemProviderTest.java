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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.EnumSet;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

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
		Files.walkFileTree(tmpPath, new DeletingFileVisitor());
	}

	@Test
	public void testGetFsViaNioApi() throws IOException {
		URI fsUri = CryptoFileSystemProvider.createCryptomatorUri(tmpPath);
		FileSystem fs = FileSystems.newFileSystem(fsUri, ImmutableMap.of(CryptoFileSystemProvider.FS_ENV_PW, "asd"));
		Assert.assertTrue(fs instanceof CryptoFileSystem);
		Assert.assertTrue(Files.exists(tmpPath.resolve("masterkey.cryptomator")));
		FileSystem fs2 = FileSystems.getFileSystem(fsUri);
		Assert.assertSame(fs, fs2);
	}

	@Test
	public void testOpenAndCloseFileChannel() throws IOException {
		Path cleartextPath = Mockito.mock(Path.class);
		Path ciphertextPath = tmpPath.resolve("foo");
		CryptoFileSystem fs = Mockito.mock(CryptoFileSystem.class);
		Cryptor cryptor = Mockito.mock(Cryptor.class);
		FileHeaderCryptor headerCryptor = Mockito.mock(FileHeaderCryptor.class);
		CryptoPathMapper pathMapper = Mockito.mock(CryptoPathMapper.class);
		OpenCryptoFiles openCryptoFiles = Mockito.mock(OpenCryptoFiles.class);
		Mockito.when(cleartextPath.getFileSystem()).thenReturn(fs);
		Mockito.when(fs.getCryptor()).thenReturn(cryptor);
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
		Mockito.when(headerCryptor.create()).thenReturn(Mockito.mock(FileHeader.class));
		Mockito.when(headerCryptor.encryptHeader(Mockito.any())).thenReturn(ByteBuffer.allocate(0));
		Mockito.when(fs.getCryptoPathMapper()).thenReturn(pathMapper);
		Mockito.when(pathMapper.getCiphertextFilePath(Mockito.any())).thenReturn(ciphertextPath);
		Mockito.when(fs.getOpenCryptoFiles()).thenReturn(openCryptoFiles);
		Mockito.when(openCryptoFiles.get(Mockito.eq(ciphertextPath), Mockito.eq(cryptor), Mockito.any())).thenAnswer(new Answer<OpenCryptoFile>() {

			@Override
			public OpenCryptoFile answer(InvocationOnMock invocation) throws Throwable {
				return OpenCryptoFile.anOpenCryptoFile().withPath(ciphertextPath).withCryptor(cryptor).withOptions(EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW))).build();
			}
		});

		try (FileChannel ch = provider.newFileChannel(cleartextPath, EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW))) {
			Assert.assertTrue(ch instanceof CryptoFileChannel);
		}
	}

}
