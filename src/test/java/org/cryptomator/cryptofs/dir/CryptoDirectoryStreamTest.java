/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.dir;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextDirectory;
import org.cryptomator.cryptofs.LongFileNameProvider;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.StringUtils;
import org.cryptomator.cryptofs.mocks.NullSecureRandom;
import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.Cryptor;
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

public class CryptoDirectoryStreamTest {

	private static final Consumer<CryptoDirectoryStream> DO_NOTHING_ON_CLOSE = ignored -> {
	};
	private static final Filter<? super Path> ACCEPT_ALL = ignored -> true;
	private static CryptorProvider CRYPTOR_PROVIDER = Cryptors.version1(NullSecureRandom.INSTANCE);

	private Cryptor cryptor;
	private FileNameCryptor filenameCryptor;
	private DirectoryStream<Path> dirStream;
	private CryptoPathMapper cryptoPathMapper;
	private LongFileNameProvider longFileNameProvider;
	private ConflictResolver conflictResolver;
	private EncryptedNamePattern encryptedNamePattern = new EncryptedNamePattern();

	@BeforeEach
	public void setup() throws IOException {
		cryptor = CRYPTOR_PROVIDER.createNew();
		filenameCryptor = cryptor.fileNameCryptor();
		dirStream = Mockito.mock(DirectoryStream.class);
		longFileNameProvider = Mockito.mock(LongFileNameProvider.class);
		conflictResolver = Mockito.mock(ConflictResolver.class);
		Mockito.when(longFileNameProvider.inflate(Mockito.any())).then(invocation -> {
			String shortName = invocation.getArgument(0);
			if (shortName.contains("invalid")) {
				throw new IOException("invalid shortened name");
			} else {
				return StringUtils.removeEnd(shortName, ".lng");
			}
		});
		cryptoPathMapper = Mockito.mock(CryptoPathMapper.class);
		FileSystem fs = Mockito.mock(FileSystem.class);
		FileSystemProvider provider = Mockito.mock(FileSystemProvider.class);
		Mockito.when(fs.provider()).thenReturn(provider);
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
	}

	@Test
	public void testDirListing() throws IOException {
		Path cleartextPath = Paths.get("/foo/bar");

		List<String> ciphertextFileNames = new ArrayList<>();
		ciphertextFileNames.add(filenameCryptor.encryptFilename(BaseEncoding.base64Url(), "one", "foo".getBytes()) + Constants.CRYPTOMATOR_FILE_SUFFIX);
		ciphertextFileNames.add(filenameCryptor.encryptFilename(BaseEncoding.base64Url(),"two", "foo".getBytes()) + " (conflict)" + Constants.CRYPTOMATOR_FILE_SUFFIX);
		ciphertextFileNames.add("?" + filenameCryptor.encryptFilename(BaseEncoding.base64Url(),"three", "foo".getBytes()) + Constants.CRYPTOMATOR_FILE_SUFFIX);
		ciphertextFileNames.add("0invalidDirectory" + Constants.CRYPTOMATOR_FILE_SUFFIX);
		ciphertextFileNames.add("0noDirectory" + Constants.CRYPTOMATOR_FILE_SUFFIX);
		ciphertextFileNames.add("invalidLongName.lng" + Constants.CRYPTOMATOR_FILE_SUFFIX);
		ciphertextFileNames.add(filenameCryptor.encryptFilename(BaseEncoding.base64Url(),"four", "foo".getBytes()) + ".lng" + Constants.CRYPTOMATOR_FILE_SUFFIX);
		ciphertextFileNames.add(filenameCryptor.encryptFilename(BaseEncoding.base64Url(),"invalid", "bar".getBytes()) + Constants.CRYPTOMATOR_FILE_SUFFIX);
		ciphertextFileNames.add("alsoInvalid");
		Mockito.when(dirStream.spliterator()).thenReturn(ciphertextFileNames.stream().map(cleartextPath::resolve).spliterator());

		try (CryptoDirectoryStream stream = new CryptoDirectoryStream("foo", dirStream, cleartextPath, cryptor, cryptoPathMapper, longFileNameProvider, conflictResolver, ACCEPT_ALL,
				DO_NOTHING_ON_CLOSE, encryptedNamePattern)) {
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

		try (CryptoDirectoryStream stream = new CryptoDirectoryStream("foo", dirStream, cleartextPath, cryptor, cryptoPathMapper, longFileNameProvider, conflictResolver, ACCEPT_ALL,
				DO_NOTHING_ON_CLOSE, encryptedNamePattern)) {
			Iterator<Path> iter = stream.iterator();
			Assertions.assertFalse(iter.hasNext());
			Assertions.assertThrows(NoSuchElementException.class, () -> {
				iter.next();
			});
		}
	}

}
