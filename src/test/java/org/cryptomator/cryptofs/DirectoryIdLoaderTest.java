package org.cryptomator.cryptofs;

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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.spi.FileSystemProvider;

import org.cryptomator.cryptofs.mocks.SeekableByteChannelMock;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class DirectoryIdLoaderTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private FileSystemProvider provider = mock(FileSystemProvider.class);
	private FileSystem fileSystem = mock(FileSystem.class);
	private Path dirFilePath = mock(Path.class);
	private Path otherDirFilePath = mock(Path.class);

	private DirectoryIdLoader inTest = new DirectoryIdLoader();

	@Before
	public void setup() {
		when(dirFilePath.getFileSystem()).thenReturn(fileSystem);
		when(otherDirFilePath.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(provider);
	}

	@Test
	public void testDirectoryIdsForTwoNonExistingFilesDiffer() throws IOException {
		doThrow(new IOException()).when(provider).checkAccess(dirFilePath);
		doThrow(new IOException()).when(provider).checkAccess(otherDirFilePath);

		String first = inTest.load(dirFilePath);
		String second = inTest.load(otherDirFilePath);

		assertThat(first, is(not(second)));
	}

	@Test
	public void testDirectoryIdForNonExistingFileIsNotEmpty() throws IOException {
		doThrow(new IOException()).when(provider).checkAccess(dirFilePath);

		String result = inTest.load(dirFilePath);

		assertThat(result, is(notNullValue()));
		assertThat(result, is(not("")));
	}

	@Test
	public void testDirectoryIdIsReadFromExistingFile() throws IOException {
		String expectedId = "asdüßT°z¬╚‗";
		byte[] expectedIdBytes = expectedId.getBytes(UTF_8);
		SeekableByteChannel channel = new SeekableByteChannelMock(ByteBuffer.wrap(expectedIdBytes));
		when(provider.newByteChannel(eq(dirFilePath), any())).thenReturn(channel);

		String result = inTest.load(dirFilePath);

		assertThat(result, is(expectedId));
	}

	@Test
	public void testIOExceptionWhenExistingFileIsEmpty() throws IOException {
		SeekableByteChannel channel = new SeekableByteChannelMock(ByteBuffer.allocate(0));
		when(provider.newByteChannel(eq(dirFilePath), any())).thenReturn(channel);

		thrown.expect(IOException.class);
		thrown.expectMessage("Invalid, empty directory file");

		inTest.load(dirFilePath);
	}

}
