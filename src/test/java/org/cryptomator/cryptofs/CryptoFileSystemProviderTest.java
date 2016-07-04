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
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;

import org.junit.Assert;
import org.junit.Test;

public class CryptoFileSystemProviderTest {

	@Test
	public void testGetProvider() throws IOException {
		Path tmpPath = Files.createTempDirectory("unit-tests");
		FileSystem fs = FileSystems.newFileSystem(URI.create("cryptomator:" + tmpPath.toString()), Collections.emptyMap());
		Assert.assertTrue(fs instanceof CryptoFileSystem);
		Files.delete(tmpPath);
	}

}
