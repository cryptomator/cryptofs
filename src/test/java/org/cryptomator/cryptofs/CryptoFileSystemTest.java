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
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.v1.CryptorProviderImpl;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

public class CryptoFileSystemTest {

	private static final SecureRandom NULL_RANDOM = new SecureRandom() {
		@Override
		public synchronized void nextBytes(byte[] bytes) {
			Arrays.fill(bytes, (byte) 0x00);
		};
	};
	private static final CryptorProviderImpl NULL_CRYPTOR_PROVIDER = new CryptorProviderImpl(NULL_RANDOM);

	@Rule
	public final ExpectedException thrown = ExpectedException.none();

	private Path tmpPath;
	private CryptoFileSystemProvider provider;

	@Before
	public void setup() throws IOException, ReflectiveOperationException {
		tmpPath = Files.createTempDirectory("unit-tests");
		provider = Mockito.mock(CryptoFileSystemProvider.class);
		ConcurrentHashMap<Path, CryptoFileSystem> openFileSystems = new ConcurrentHashMap<>();
		Mockito.when(provider.getFileSystems()).thenReturn(openFileSystems);
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
	public void testConstructorForNewVault() throws IOException {
		CryptoFileSystem fs = new CryptoFileSystem(provider, NULL_CRYPTOR_PROVIDER, tmpPath, "foo", false);
		fs.close();
	}

	@Test
	public void testConstructorForExistingVault() throws IOException {
		CryptoFileSystem fs = new CryptoFileSystem(provider, NULL_CRYPTOR_PROVIDER, tmpPath, "foo", false);
		fs.close();

		CryptoFileSystem fs2 = new CryptoFileSystem(provider, NULL_CRYPTOR_PROVIDER, tmpPath, "foo", false);
		fs2.close();
	}

	@Test
	public void testConstructorForExistingVaultWithWrongPw() throws IOException {
		CryptoFileSystem fs = new CryptoFileSystem(provider, NULL_CRYPTOR_PROVIDER, tmpPath, "foo", false);
		fs.close();

		thrown.expect(InvalidPassphraseException.class);
		CryptoFileSystem fs2 = new CryptoFileSystem(provider, NULL_CRYPTOR_PROVIDER, tmpPath, "bar", false);
		fs2.close();
	}

}
