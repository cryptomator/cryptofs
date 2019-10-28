/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.dir;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Spliterators;
import java.util.function.Consumer;
import java.util.stream.Stream;

public class CryptoDirectoryStreamTest {

	private static final Consumer<CryptoDirectoryStream> DO_NOTHING_ON_CLOSE = ignored -> {
	};
	private static final Filter<? super Path> ACCEPT_ALL = ignored -> true;
	
	private NodeProcessor nodeProcessor;
	private DirectoryStream<Path> dirStream;

	@BeforeEach
	public void setup() throws IOException {
		nodeProcessor = Mockito.mock(NodeProcessor.class);
		dirStream = Mockito.mock(DirectoryStream.class);
	}
	
	private ArgumentMatcher<Node> nodeNamed(String name) {
		return node -> node.fullCiphertextFileName.equals(name);
	}

	@Test
	public void testDirListing() throws IOException {
		Path ciphertextPath = Paths.get("/f00/b4r");
		Path cleartextPath = Paths.get("/foo/bar");
		List<String> ciphertextFileNames = new ArrayList<>();
		ciphertextFileNames.add("ciphertextFile1");
		ciphertextFileNames.add("ciphertextFile2");
		ciphertextFileNames.add("ciphertextDirectory1");
		ciphertextFileNames.add("invalidCiphertext");
		Mockito.when(dirStream.spliterator()).thenReturn(ciphertextFileNames.stream().map(ciphertextPath::resolve).spliterator());
		Mockito.doAnswer(invocation -> {
			Node node = invocation.getArgument(0);
			node.cleartextName = "cleartextFile1";
			return Stream.of(node);
		}).when(nodeProcessor).process(Mockito.argThat(node -> node.fullCiphertextFileName.equals("ciphertextFile1")));
		Mockito.doAnswer(invocation -> {
			Node node = invocation.getArgument(0);
			node.cleartextName = "cleartextFile2";
			return Stream.of(node);
		}).when(nodeProcessor).process(Mockito.argThat(node -> node.fullCiphertextFileName.equals("ciphertextFile2")));
		Mockito.doAnswer(invocation -> {
			Node node = invocation.getArgument(0);
			node.cleartextName = "cleartextDirectory1";
			return Stream.of(node);
		}).when(nodeProcessor).process(Mockito.argThat(node -> node.fullCiphertextFileName.equals("ciphertextDirectory1")));
		Mockito.doAnswer(invocation -> {
			return Stream.empty();
		}).when(nodeProcessor).process(Mockito.argThat(node -> node.fullCiphertextFileName.equals("invalidCiphertext")));
		
		try (CryptoDirectoryStream stream = new CryptoDirectoryStream("foo", dirStream, cleartextPath, ACCEPT_ALL, DO_NOTHING_ON_CLOSE, nodeProcessor)) {
			Iterator<Path> iter = stream.iterator();
			Assertions.assertTrue(iter.hasNext());
			Assertions.assertEquals(cleartextPath.resolve("cleartextFile1"), iter.next());
			Assertions.assertTrue(iter.hasNext());
			Assertions.assertEquals(cleartextPath.resolve("cleartextFile2"), iter.next());
			Assertions.assertTrue(iter.hasNext());
			Assertions.assertEquals(cleartextPath.resolve("cleartextDirectory1"), iter.next());
			Assertions.assertFalse(iter.hasNext());
			Mockito.verify(dirStream, Mockito.never()).close();
		}
		Mockito.verify(dirStream).close();
	}

	@Test
	public void testDirListingForEmptyDir() throws IOException {
		Path cleartextPath = Paths.get("/foo/bar");

		Mockito.when(dirStream.spliterator()).thenReturn(Spliterators.emptySpliterator());

		try (CryptoDirectoryStream stream = new CryptoDirectoryStream("foo", dirStream, cleartextPath, ACCEPT_ALL, DO_NOTHING_ON_CLOSE, nodeProcessor)) {
			Iterator<Path> iter = stream.iterator();
			Assertions.assertFalse(iter.hasNext());
			Assertions.assertThrows(NoSuchElementException.class, () -> {
				iter.next();
			});
		}
	}

}
