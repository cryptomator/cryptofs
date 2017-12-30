package org.cryptomator.cryptofs;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.spi.AbstractInterruptibleChannel;
import java.nio.file.FileSystem;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.spi.FileSystemProvider;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DirectoryIdLoaderTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private final FileSystemProvider provider = mock(FileSystemProvider.class);
	private final FileSystem fileSystem = mock(FileSystem.class);
	private final Path dirFilePath = mock(Path.class);
	private final Path otherDirFilePath = mock(Path.class);

	private final DirectoryIdLoader inTest = new DirectoryIdLoader();

	@Before
	public void setup() {
		when(dirFilePath.getFileSystem()).thenReturn(fileSystem);
		when(otherDirFilePath.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(provider);
	}

	@Test
	public void testDirectoryIdsForTwoNonExistingFilesDiffer() throws IOException {
		doThrow(new NoSuchFileException("foo")).when(provider).newFileChannel(eq(dirFilePath), any());
		doThrow(new NoSuchFileException("bar")).when(provider).newFileChannel(eq(otherDirFilePath), any());

		String first = inTest.load(dirFilePath);
		String second = inTest.load(otherDirFilePath);

		assertThat(first, is(not(second)));
	}

	@Test
	public void testDirectoryIdForNonExistingFileIsNotEmpty() throws IOException {
		doThrow(new NoSuchFileException("foo")).when(provider).newFileChannel(eq(dirFilePath), any());

		String result = inTest.load(dirFilePath);

		assertThat(result, is(notNullValue()));
		assertThat(result, is(not("")));
	}

	@Test
	public void testDirectoryIdIsReadFromExistingFile() throws IOException, ReflectiveOperationException {
		String expectedId = "asdüßT°z¬╚‗";
		byte[] expectedIdBytes = expectedId.getBytes(UTF_8);
		FileChannel channel = createFileChannelMock();
		when(provider.newFileChannel(eq(dirFilePath), any())).thenReturn(channel);
		when(channel.size()).thenReturn((long) expectedIdBytes.length);
		when(channel.read(any(ByteBuffer.class))).then(invocation -> {
			ByteBuffer buf = invocation.getArgument(0);
			buf.put(expectedIdBytes);
			return expectedIdBytes.length;
		});

		String result = inTest.load(dirFilePath);

		assertThat(result, is(expectedId));
	}

	@Test
	public void testIOExceptionWhenExistingFileIsEmpty() throws IOException, ReflectiveOperationException {
		FileChannel channel = createFileChannelMock();
		when(provider.newFileChannel(eq(dirFilePath), any())).thenReturn(channel);
		when(channel.size()).thenReturn(0l);

		thrown.expect(IOException.class);
		thrown.expectMessage("Invalid, empty directory file");

		inTest.load(dirFilePath);
	}

	@Test
	public void testIOExceptionWhenExistingFileIsTooLarge() throws IOException, ReflectiveOperationException {
		FileChannel channel = createFileChannelMock();
		when(provider.newFileChannel(eq(dirFilePath), any())).thenReturn(channel);
		when(channel.size()).thenReturn((long) Integer.MAX_VALUE);

		thrown.expect(IOException.class);
		thrown.expectMessage("Unexpectedly large directory file");

		inTest.load(dirFilePath);
	}

	private FileChannel createFileChannelMock() throws ReflectiveOperationException {
		FileChannel channel = Mockito.mock(FileChannel.class);
		Field channelClosedField = AbstractInterruptibleChannel.class.getDeclaredField("closed");
		channelClosedField.setAccessible(true);
		channelClosedField.set(channel, false);
		Field channelCloseLockField = AbstractInterruptibleChannel.class.getDeclaredField("closeLock");
		channelCloseLockField.setAccessible(true);
		channelCloseLockField.set(channel, new Object());
		return channel;
	}

}
