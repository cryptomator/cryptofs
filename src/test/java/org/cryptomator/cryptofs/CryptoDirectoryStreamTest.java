/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextDirectory;
import org.cryptomator.cryptofs.mocks.NullSecureRandom;
import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Spliterators;
import java.util.function.Consumer;

import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

public class CryptoDirectoryStreamTest {

	private static final Consumer<CryptoDirectoryStream> DO_NOTHING_ON_CLOSE = ignored -> {
	};
	private static final Filter<? super Path> ACCEPT_ALL = ignored -> true;
	private static CryptorProvider CRYPTOR_PROVIDER = Cryptors.version1(NullSecureRandom.INSTANCE);

	private FileNameCryptor filenameCryptor;
	private Path ciphertextDirPath;
	private DirectoryStream<Path> dirStream;
	private CryptoPathMapper cryptoPathMapper;
	private LongFileNameProvider longFileNameProvider;
	private ConflictResolver conflictResolver;
	private FinallyUtil finallyUtil;
	private EncryptedNamePattern encryptedNamePattern = new EncryptedNamePattern();

	@BeforeEach
	@SuppressWarnings("unchecked")
	public void setup() throws IOException {
		filenameCryptor = CRYPTOR_PROVIDER.createNew().fileNameCryptor();

		ciphertextDirPath = Mockito.mock(Path.class);
		FileSystem fs = Mockito.mock(FileSystem.class);
		Mockito.when(ciphertextDirPath.getFileSystem()).thenReturn(fs);
		FileSystemProvider provider = Mockito.mock(FileSystemProvider.class);
		Mockito.when(fs.provider()).thenReturn(provider);
		dirStream = Mockito.mock(DirectoryStream.class);
		Mockito.when(provider.newDirectoryStream(Mockito.same(ciphertextDirPath), Mockito.any())).thenReturn(dirStream);
		longFileNameProvider = Mockito.mock(LongFileNameProvider.class);
		conflictResolver = Mockito.mock(ConflictResolver.class);
		finallyUtil = mock(FinallyUtil.class);
		Mockito.when(longFileNameProvider.inflate(Mockito.anyString())).then(invocation -> {
			String shortName = invocation.getArgument(0);
			if (shortName.contains("invalid")) {
				throw new IOException("invalid shortened name");
			} else {
				return StringUtils.removeEnd(shortName, ".lng");
			}
		});
		cryptoPathMapper = Mockito.mock(CryptoPathMapper.class);
		Mockito.when(cryptoPathMapper.resolveDirectory(Mockito.any())).then(invocation -> {
			Path dirFilePath = invocation.getArgument(0);
			if (dirFilePath.toString().contains("invalid")) {
				throw new IOException("Invalid directory.");
			}
			Path dirPath = Mockito.mock(Path.class);
			BasicFileAttributes attrs = Mockito.mock(BasicFileAttributes.class);
			Mockito.when(dirPath.getFileSystem()).thenReturn(fs);
			Mockito.when(provider.readAttributes(dirPath, BasicFileAttributes.class)).thenReturn(attrs);
			Mockito.when(attrs.isDirectory()).thenReturn(!dirFilePath.toString().contains("noDirectory"));
			return new CiphertextDirectory("asdf", dirPath);
		});

		Mockito.when(conflictResolver.resolveConflictsIfNecessary(Mockito.any(), Mockito.any())).then(returnsFirstArg());

		doAnswer(invocation -> {
			for (Object runnable : invocation.getArguments()) {
				((RunnableThrowingException<?>) runnable).run();
			}
			return null;
		}).when(finallyUtil).guaranteeInvocationOf(any(RunnableThrowingException.class), any(RunnableThrowingException.class), any(RunnableThrowingException.class));
	}

	@Test
	public void testDirListing() throws IOException {
		Path cleartextPath = Paths.get("/foo/bar");

		List<String> ciphertextFileNames = new ArrayList<>();
		ciphertextFileNames.add(filenameCryptor.encryptFilename("one", "foo".getBytes()));
		ciphertextFileNames.add(filenameCryptor.encryptFilename("two", "foo".getBytes()) + "_conflict");
		ciphertextFileNames.add("0" + filenameCryptor.encryptFilename("three", "foo".getBytes()));
		ciphertextFileNames.add("0invalidDirectory");
		ciphertextFileNames.add("0noDirectory");
		ciphertextFileNames.add("invalidLongName.lng");
		ciphertextFileNames.add(filenameCryptor.encryptFilename("four", "foo".getBytes()) + ".lng");
		ciphertextFileNames.add(filenameCryptor.encryptFilename("invalid", "bar".getBytes()));
		ciphertextFileNames.add("alsoInvalid");
		Mockito.when(dirStream.spliterator()).thenReturn(ciphertextFileNames.stream().map(cleartextPath::resolve).spliterator());

		try (CryptoDirectoryStream stream = new CryptoDirectoryStream(new CiphertextDirectory("foo", ciphertextDirPath), cleartextPath, filenameCryptor, cryptoPathMapper, longFileNameProvider, conflictResolver, ACCEPT_ALL,
				DO_NOTHING_ON_CLOSE, finallyUtil, encryptedNamePattern)) {
			Iterator<Path> iter = stream.iterator();
			Assertions.assertTrue(iter.hasNext());
			Assertions.assertEquals(cleartextPath.resolve("one"), iter.next());
			Assertions.assertTrue(iter.hasNext());
			Assertions.assertEquals(cleartextPath.resolve("two"), iter.next());
			Assertions.assertTrue(iter.hasNext());
			Assertions.assertEquals(cleartextPath.resolve("three"), iter.next());
			Assertions.assertTrue(iter.hasNext());
			Assertions.assertEquals(cleartextPath.resolve("four"), iter.next());
			Assertions.assertFalse(iter.hasNext());
			Mockito.verify(dirStream, Mockito.never()).close();
		}
		Mockito.verify(dirStream).close();
	}

	@Test
	public void testDirListingForEmptyDir() throws IOException {
		Path cleartextPath = Paths.get("/foo/bar");

		Mockito.when(dirStream.spliterator()).thenReturn(Spliterators.emptySpliterator());

		try (CryptoDirectoryStream stream = new CryptoDirectoryStream(new CiphertextDirectory("foo", ciphertextDirPath), cleartextPath, filenameCryptor, cryptoPathMapper, longFileNameProvider, conflictResolver, ACCEPT_ALL,
				DO_NOTHING_ON_CLOSE, finallyUtil, encryptedNamePattern)) {
			Iterator<Path> iter = stream.iterator();
			Assertions.assertFalse(iter.hasNext());
			Assertions.assertThrows(NoSuchElementException.class, () -> {
				iter.next();
			});
		}
	}

}
