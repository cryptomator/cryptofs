package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.spi.FileSystemProvider;

import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;

public class ConflictResolverTest {

	private LongFileNameProvider longFileNameProvider;
	private FileNameCryptor filenameCryptor;
	private ConflictResolver conflictResolver;
	private String dirId;
	private Path testFile;
	private Path testFileName;
	private Path testDir;
	private FileSystem testFileSystem;
	private FileSystemProvider testFileSystemProvider;

	@Before
	public void setup() {
		this.longFileNameProvider = Mockito.mock(LongFileNameProvider.class);
		this.filenameCryptor = Mockito.mock(FileNameCryptor.class);
		this.conflictResolver = new ConflictResolver(longFileNameProvider, filenameCryptor);
		this.dirId = "foo";
		this.testFile = Mockito.mock(Path.class);
		this.testFileName = Mockito.mock(Path.class);
		this.testDir = Mockito.mock(Path.class);
		this.testFileSystem = Mockito.mock(FileSystem.class);
		this.testFileSystemProvider = Mockito.mock(FileSystemProvider.class);

		Mockito.when(testFile.getParent()).thenReturn(testDir);
		Mockito.when(testFile.getFileName()).thenReturn(testFileName);
		Mockito.when(testDir.resolve(Mockito.anyString())).then(this::resolveChildOfTestDir);
		Mockito.when(testFile.resolveSibling(Mockito.anyString())).then(this::resolveChildOfTestDir);
		Mockito.when(testFile.getFileSystem()).thenReturn(testFileSystem);
		Mockito.when(testFileSystem.provider()).thenReturn(testFileSystemProvider);
	}

	private Path resolveChildOfTestDir(InvocationOnMock invocation) {
		Path result = Mockito.mock(Path.class);
		Path resultName = Mockito.mock(Path.class);
		Mockito.when(result.getFileName()).thenReturn(resultName);
		Mockito.when(resultName.toString()).thenReturn(invocation.getArgument(0));
		Mockito.when(result.getParent()).thenReturn(testDir);
		Mockito.when(result.getFileSystem()).thenReturn(testFileSystem);
		return result;
	}

	@Test
	public void testPassthroughValidBase32NormalFile() throws IOException {
		Mockito.when(testFileName.toString()).thenReturn("ABCDEF==");
		Path resolved = conflictResolver.resolveConflicts(testFile, dirId);
		Mockito.verifyNoMoreInteractions(filenameCryptor);
		Mockito.verifyNoMoreInteractions(longFileNameProvider);
		Assert.assertEquals(testFile.getFileName().toString(), resolved.getFileName().toString());
	}

	@Test
	public void testPassthroughValidBase32LongFile() throws IOException {
		Mockito.when(testFileName.toString()).thenReturn("ABCDEF==.lng");
		Path resolved = conflictResolver.resolveConflicts(testFile, dirId);
		Mockito.verifyNoMoreInteractions(filenameCryptor);
		Mockito.verifyNoMoreInteractions(longFileNameProvider);
		Assert.assertEquals(testFile.getFileName().toString(), resolved.getFileName().toString());
	}

	@Test
	public void testAlternativeNameForNormalFile() throws IOException {
		String ciphertextName = "ABCDEFGH2345====";
		Mockito.when(testFileName.toString()).thenReturn("ABCDEF== (1)");
		Mockito.when(filenameCryptor.decryptFilename(Mockito.eq("ABCDEF=="), Mockito.any())).thenReturn("abcdef");
		Mockito.when(filenameCryptor.encryptFilename(Mockito.startsWith("abcdef (Conflict "), Mockito.any())).thenReturn(ciphertextName);
		Mockito.doThrow(new NoSuchFileException(ciphertextName)).when(testFileSystemProvider).checkAccess(Mockito.argThat(p -> p.getFileName().toString().equals(ciphertextName)));
		Path resolved = conflictResolver.resolveConflicts(testFile, dirId);
		Mockito.verifyNoMoreInteractions(longFileNameProvider);
		Assert.assertThat(resolved.getFileName().toString(), CoreMatchers.containsString(ciphertextName));
	}

	@Test
	public void testAlternativeNameForLongFile() throws IOException {
		String longCiphertextName = "ABCDEFGHABCDEFGHABCDEFGHABCDEFGHABCDEFGHABCDEFGHABCDEFGHABCDEFGHABCDEFGHABCDEFGHABCDEFGHABCDEFGHABCDEFGHABCDEFGHABCDEFGHABCDEFGH2345====";
		assert longCiphertextName.length() > Constants.NAME_SHORTENING_THRESHOLD;
		Mockito.when(testFileName.toString()).thenReturn("ABCDEF== (1).lng");
		Mockito.when(longFileNameProvider.inflate("ABCDEF==.lng")).thenReturn("FEDCBA==");
		Mockito.when(longFileNameProvider.deflate(longCiphertextName)).thenReturn("FEDCBA==.lng");
		Mockito.when(filenameCryptor.decryptFilename(Mockito.eq("FEDCBA=="), Mockito.any())).thenReturn("fedcba");
		Mockito.when(filenameCryptor.encryptFilename(Mockito.startsWith("fedcba (Conflict "), Mockito.any())).thenReturn(longCiphertextName);
		Mockito.doThrow(new NoSuchFileException(longCiphertextName)).when(testFileSystemProvider).checkAccess(Mockito.argThat(p -> p.getFileName().toString().equals("FEDCBA==.lng")));
		Path resolved = conflictResolver.resolveConflicts(testFile, dirId);
		Mockito.verify(longFileNameProvider).deflate(longCiphertextName);
		Assert.assertThat(resolved.getFileName().toString(), CoreMatchers.containsString("FEDCBA==.lng"));
	}

}
