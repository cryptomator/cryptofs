package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.CryptoPathMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

class BrokenDirectoryFilterTest {

	private CryptoPathMapper cryptoPathMapper = Mockito.mock(CryptoPathMapper.class);
	private BrokenDirectoryFilter brokenDirectoryFilter = new BrokenDirectoryFilter(cryptoPathMapper);

	@Test
	public void testProcessNonDirectoryNode(@TempDir Path dir) {
		Node unfiltered = new Node(dir.resolve("foo.c9r"));
		
		Stream<Node> result = brokenDirectoryFilter.process(unfiltered);
		Node filtered = result.findAny().get();

		Assertions.assertSame(unfiltered, filtered);
	}

	@Test
	public void testProcessNormalDirectoryNode(@TempDir Path dir) throws IOException {
		Path targetDir = Files.createDirectories(dir.resolve("d/ab/cdefg"));
		Files.createDirectory(dir.resolve("foo.c9r"));
		Files.write(dir.resolve("foo.c9r/dir.c9r"), "".getBytes());
		Mockito.when(cryptoPathMapper.resolveDirectory(Mockito.any())).thenReturn(new CryptoPathMapper.CiphertextDirectory("asd", targetDir));
		Node unfiltered = new Node(dir.resolve("foo.c9r"));

		Stream<Node> result = brokenDirectoryFilter.process(unfiltered);
		Node filtered = result.findAny().get();

		Assertions.assertSame(unfiltered, filtered);
	}

	@Test
	public void testProcessNodeWithMissingTargetDir(@TempDir Path dir) throws IOException {
		Path targetDir = dir.resolve("d/ab/cdefg"); // not existing!
		Files.createDirectory(dir.resolve("foo.c9r"));
		Files.write(dir.resolve("foo.c9r/dir.c9r"), "".getBytes());
		Mockito.when(cryptoPathMapper.resolveDirectory(Mockito.any())).thenReturn(new CryptoPathMapper.CiphertextDirectory("asd", targetDir));
		Node unfiltered = new Node(dir.resolve("foo.c9r"));

		Stream<Node> result = brokenDirectoryFilter.process(unfiltered);
		Assertions.assertFalse(result.findAny().isPresent());
	}

}