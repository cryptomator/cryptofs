/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.Constants.SHORT_NAMES_MAX_LENGTH;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.cryptomator.cryptofs.CryptoDirectoryStream.ProcessedPaths;
import org.cryptomator.cryptofs.CryptoPathMapper.Directory;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import com.google.common.jimfs.Jimfs;

public class CryptoDirectoryStreamIntegrationTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	private FileSystem fileSystem;

	private LongFileNameProvider longFileNameProvider = mock(LongFileNameProvider.class);

	private CryptoDirectoryStream inTest;

	@Before
	public void setup() throws IOException {
		fileSystem = Jimfs.newFileSystem();

		Path dir = fileSystem.getPath("crapDirDoNotUse");
		Files.createDirectory(dir);
		inTest = new CryptoDirectoryStream(new Directory("", dir), null, null, null, longFileNameProvider, null, null, null, null, null);
	}

	@Test
	public void testInflateIfNeededWithShortFilename() throws IOException {
		String filename = "abc";
		Path ciphertextPath = fileSystem.getPath(filename);
		Files.createFile(ciphertextPath);
		when(longFileNameProvider.isDeflated(filename)).thenReturn(false);

		ProcessedPaths paths = new ProcessedPaths(ciphertextPath);

		ProcessedPaths result = inTest.inflateIfNeeded(paths);

		assertThat(result.getCiphertextPath(), is(ciphertextPath));
		assertThat(result.getInflatedPath(), is(ciphertextPath));
		assertThat(result.getCleartextPath(), is(nullValue()));
		assertThat(Files.exists(ciphertextPath), is(true));
	}

	@Test
	public void testInflateIfNeededWithRegularLongFilename() throws IOException {
		String filename = "abc";
		String inflatedName = IntStream.range(0, SHORT_NAMES_MAX_LENGTH + 1).mapToObj(ignored -> "a").collect(Collectors.joining());
		Path ciphertextPath = fileSystem.getPath(filename);
		Files.createFile(ciphertextPath);
		Path inflatedPath = fileSystem.getPath(inflatedName);
		when(longFileNameProvider.isDeflated(filename)).thenReturn(true);
		when(longFileNameProvider.inflate(filename)).thenReturn(inflatedName);

		ProcessedPaths paths = new ProcessedPaths(ciphertextPath);

		ProcessedPaths result = inTest.inflateIfNeeded(paths);

		assertThat(result.getCiphertextPath(), is(ciphertextPath));
		assertThat(result.getInflatedPath(), is(inflatedPath));
		assertThat(result.getCleartextPath(), is(nullValue()));
		assertThat(Files.exists(ciphertextPath), is(true));
		assertThat(Files.exists(inflatedPath), is(false));
	}

	@Test
	public void testInflateIfNeededWithLongFilenameThatShouldActuallyBeShort() throws IOException {
		String filename = "abc";
		String inflatedName = IntStream.range(0, SHORT_NAMES_MAX_LENGTH).mapToObj(ignored -> "a").collect(Collectors.joining());
		Path ciphertextPath = fileSystem.getPath(filename);
		Files.createFile(ciphertextPath);
		Path inflatedPath = fileSystem.getPath(inflatedName);
		when(longFileNameProvider.isDeflated(filename)).thenReturn(true);
		when(longFileNameProvider.inflate(filename)).thenReturn(inflatedName);

		ProcessedPaths paths = new ProcessedPaths(ciphertextPath);

		ProcessedPaths result = inTest.inflateIfNeeded(paths);

		assertThat(result.getCiphertextPath(), is(inflatedPath));
		assertThat(result.getInflatedPath(), is(inflatedPath));
		assertThat(result.getCleartextPath(), is(nullValue()));
		assertThat(Files.exists(ciphertextPath), is(false));
		assertThat(Files.exists(inflatedPath), is(true));
	}

}
