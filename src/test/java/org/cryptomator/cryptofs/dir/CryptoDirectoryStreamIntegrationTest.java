/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.dir;

import com.google.common.base.Strings;
import org.cryptomator.cryptofs.LongFileNameProvider;
import org.cryptomator.cryptolib.api.Cryptor;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.cryptomator.cryptofs.common.Constants.MAX_CIPHERTEXT_NAME_LENGTH;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CryptoDirectoryStreamIntegrationTest {
	
	private LongFileNameProvider longFileNameProvider = mock(LongFileNameProvider.class);

	private CryptoDirectoryStream inTest;

	@BeforeEach
	public void setup() throws IOException {
		inTest = new CryptoDirectoryStream("foo", null,null, Mockito.mock(Cryptor.class), null, longFileNameProvider, null, null, null, null);
	}

	@Test
	public void testInflateIfNeededWithShortFilename() {
		String filename = "abc";
		Path ciphertextPath = Paths.get(filename);
		when(longFileNameProvider.isDeflated(filename)).thenReturn(false);

		NodeNames paths = new NodeNames(ciphertextPath);

		NodeNames result = inTest.inflateIfNeeded(paths);

		MatcherAssert.assertThat(result.getCiphertextPath(), is(ciphertextPath));
		MatcherAssert.assertThat(result.getInflatedPath(), is(ciphertextPath));
		MatcherAssert.assertThat(result.getCleartextPath(), is(nullValue()));
	}

	@Test
	public void testInflateIfNeededWithRegularLongFilename() throws IOException {
		String filename = "abc";
		String inflatedName = Strings.repeat("a", MAX_CIPHERTEXT_NAME_LENGTH + 1);
		Path ciphertextPath = Paths.get(filename);
		Path inflatedPath = Paths.get(inflatedName);
		when(longFileNameProvider.isDeflated(filename)).thenReturn(true);
		when(longFileNameProvider.inflate(ciphertextPath)).thenReturn(inflatedName);

		NodeNames paths = new NodeNames(ciphertextPath);

		NodeNames result = inTest.inflateIfNeeded(paths);

		MatcherAssert.assertThat(result.getCiphertextPath(), is(ciphertextPath));
		MatcherAssert.assertThat(result.getInflatedPath(), is(inflatedPath));
		MatcherAssert.assertThat(result.getCleartextPath(), is(nullValue()));
	}

}
