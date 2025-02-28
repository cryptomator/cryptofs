package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.event.BrokenDirFileEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystem;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.spi.FileSystemProvider;
import java.util.function.Consumer;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class DirectoryIdLoaderTest {

	private final FileSystemProvider provider = mock(FileSystemProvider.class);
	private final FileSystem fileSystem = mock(FileSystem.class);
	private final Path dirFilePath = mock(Path.class);
	private final Path otherDirFilePath = mock(Path.class);
	private final Consumer<FilesystemEvent> eventConsumer = mock(Consumer.class);

	private final DirectoryIdLoader inTest = new DirectoryIdLoader(eventConsumer);

	@BeforeEach
	public void setup() {
		when(dirFilePath.getFileSystem()).thenReturn(fileSystem);
		when(otherDirFilePath.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(provider);
		doNothing().when(eventConsumer).accept(any());
	}

	@Test
	public void testDirectoryIdsForTwoNonExistingFilesDiffer() throws IOException {
		doThrow(new NoSuchFileException("foo")).when(provider).newFileChannel(eq(dirFilePath), any());
		doThrow(new NoSuchFileException("bar")).when(provider).newFileChannel(eq(otherDirFilePath), any());

		String first = inTest.load(dirFilePath);
		String second = inTest.load(otherDirFilePath);

		Assertions.assertNotEquals(second, first);
	}

	@Test
	public void testDirectoryIdForNonExistingFileIsNotEmpty() throws IOException {
		doThrow(new NoSuchFileException("foo")).when(provider).newFileChannel(eq(dirFilePath), any());

		String result = inTest.load(dirFilePath);

		Assertions.assertNotNull(result);
		Assertions.assertNotEquals("", result);
	}

	@Test
	public void testDirectoryIdIsReadFromExistingFile() throws IOException {
		String expectedId = "asdüßT°z¬╚‗";
		byte[] expectedIdBytes = expectedId.getBytes(UTF_8);
		FileChannel channel = Mockito.mock(FileChannel.class);
		when(provider.newFileChannel(eq(dirFilePath), any())).thenReturn(channel);
		when(channel.size()).thenReturn((long) expectedIdBytes.length);
		when(channel.read(any(ByteBuffer.class))).then(invocation -> {
			ByteBuffer buf = invocation.getArgument(0);
			buf.put(expectedIdBytes);
			return expectedIdBytes.length;
		});

		String result = inTest.load(dirFilePath);

		Assertions.assertEquals(expectedId, result);
	}

	@Test
	public void testIOExceptionWhenExistingFileIsEmpty() throws IOException {
		FileChannel channel = Mockito.mock(FileChannel.class);
		when(provider.newFileChannel(eq(dirFilePath), any())).thenReturn(channel);
		when(channel.size()).thenReturn(0l);

		var ioException = Assertions.assertThrows(IOException.class, () -> {
			inTest.load(dirFilePath);
		});
		MatcherAssert.assertThat(ioException.getMessage(), containsString("Invalid, empty directory file"));
		var isBrokenDirFileEvent = (ArgumentMatcher<FilesystemEvent>) ev -> ev instanceof BrokenDirFileEvent;
		verify(eventConsumer).accept(ArgumentMatchers.argThat(isBrokenDirFileEvent));
	}

	@Test
	public void testIOExceptionWhenExistingFileIsTooLarge() throws IOException {
		FileChannel channel = Mockito.mock(FileChannel.class);
		when(provider.newFileChannel(eq(dirFilePath), any())).thenReturn(channel);
		when(channel.size()).thenReturn((long) Integer.MAX_VALUE);

		var ioException = Assertions.assertThrows(IOException.class, () -> {
			inTest.load(dirFilePath);
		});
		MatcherAssert.assertThat(ioException.getMessage(), containsString("Unexpectedly large directory file"));
		var isBrokenDirFileEvent = (ArgumentMatcher<FilesystemEvent>) ev -> ev instanceof BrokenDirFileEvent;
		verify(eventConsumer).accept(ArgumentMatchers.argThat(isBrokenDirFileEvent));
	}

}
