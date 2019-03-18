package org.cryptomator.cryptofs;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.CryptoFileSystemProperties.FileSystemFlags;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.ByteChannel;
import java.nio.channels.FileChannel;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.ProviderMismatchException;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.stream.Stream;

import static java.nio.file.Paths.get;
import static java.nio.file.StandardOpenOption.APPEND;
import static java.util.Arrays.asList;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.cryptomator.cryptofs.CryptoFileSystemProvider.containsVault;
import static org.cryptomator.cryptofs.CryptoFileSystemProvider.newFileSystem;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CryptoFileSystemProviderTest {

	private final CryptoFileSystems fileSystems = mock(CryptoFileSystems.class);

	private final CryptoPath cryptoPath = mock(CryptoPath.class);
	private final CryptoPath secondCryptoPath = mock(CryptoPath.class);
	private final CryptoPath relativeCryptoPath = mock(CryptoPath.class);
	private final CryptoFileSystemImpl cryptoFileSystem = mock(CryptoFileSystemImpl.class);
	private final CopyOperation copyOperation = mock(CopyOperation.class);
	private final MoveOperation moveOperation = mock(MoveOperation.class);

	private final Path otherPath = mock(Path.class);
	private final FileSystem otherFileSystem = mock(FileSystem.class);
	private final FileSystemProvider otherProvider = mock(FileSystemProvider.class);

	private CryptoFileSystemProvider inTest;

	private static final Stream<InvocationWhichShouldFail> shouldFailWithProviderMismatch() {
		return Stream.of( //
				invocation("newAsynchronousFileChannel", (inTest, path) -> inTest.newAsynchronousFileChannel(path, new HashSet<>(), mock(ExecutorService.class))), //
				invocation("newFileChannel", (inTest, path) -> inTest.newFileChannel(path, new HashSet<>())), //
				invocation("newByteChannel", (inTest, path) -> inTest.newByteChannel(path, new HashSet<>())), //
				invocation("newDirectoryStream", (inTest, path) -> inTest.newDirectoryStream(path, mock(Filter.class))), //
				invocation("createDirectory", (inTest, path) -> inTest.createDirectory(path)), //
				invocation("delete", (inTest, path) -> inTest.delete(path)), //
				invocation("copy", (inTest, path) -> inTest.copy(path, path)), //
				invocation("move", (inTest, path) -> inTest.move(path, path)), //
				invocation("isHidden", (inTest, path) -> inTest.isHidden(path)), //
				invocation("getFileStore", (inTest, path) -> inTest.getFileStore(path)), //
				invocation("checkAccess", (inTest, path) -> inTest.checkAccess(path)), //
				invocation("getFileAttributeView", (inTest, path) -> inTest.getFileAttributeView(path, FileAttributeView.class)), //
				invocation("readAttributesWithClass", (inTest, path) -> inTest.readAttributes(path, BasicFileAttributes.class)), //
				invocation("readAttributesWithString", (inTest, path) -> inTest.readAttributes(path, "fooBar")), //
				invocation("setAttribute", (inTest, path) -> inTest.setAttribute(path, "a", "b")) //
		);
	}

	@SuppressWarnings("unchecked")
	private static final Stream<InvocationWhichShouldFail> shouldFailWithRelativePath() {
		return Stream.of( //
				invocation("newAsynchronousFileChannel", (inTest, path) -> inTest.newAsynchronousFileChannel(path, new HashSet<>(), mock(ExecutorService.class))), //
				invocation("newFileChannel", (inTest, path) -> inTest.newFileChannel(path, new HashSet<>())), //
				invocation("newByteChannel", (inTest, path) -> inTest.newByteChannel(path, new HashSet<>())), //
				invocation("newDirectoryStream", (inTest, path) -> inTest.newDirectoryStream(path, mock(Filter.class))), //
				invocation("createDirectory", (inTest, path) -> inTest.createDirectory(path)), //
				invocation("delete", (inTest, path) -> inTest.delete(path)), //
				invocation("copy", (inTest, path) -> inTest.copy(path, path)), //
				invocation("move", (inTest, path) -> inTest.move(path, path)), //
				invocation("isHidden", (inTest, path) -> inTest.isHidden(path)), //
				invocation("checkAccess", (inTest, path) -> inTest.checkAccess(path)), //
				invocation("getFileAttributeView", (inTest, path) -> inTest.getFileAttributeView(path, FileAttributeView.class)), //
				invocation("readAttributesWithClass", (inTest, path) -> inTest.readAttributes(path, BasicFileAttributes.class)), //
				invocation("readAttributesWithString", (inTest, path) -> inTest.readAttributes(path, "fooBar")), //
				invocation("setAttribute", (inTest, path) -> inTest.setAttribute(path, "a", "b")) //
		);
	}

	@BeforeEach
	@SuppressWarnings("deprecation")
	public void setup() {
		CryptoFileSystemProviderComponent component = mock(CryptoFileSystemProviderComponent.class);
		when(component.fileSystems()).thenReturn(fileSystems);
		when(component.copyOperation()).thenReturn(copyOperation);
		when(component.moveOperation()).thenReturn(moveOperation);
		inTest = new CryptoFileSystemProvider(component);

		when(cryptoPath.isAbsolute()).thenReturn(true);
		when(cryptoPath.getFileSystem()).thenReturn(cryptoFileSystem);
		when(secondCryptoPath.isAbsolute()).thenReturn(true);
		when(secondCryptoPath.getFileSystem()).thenReturn(cryptoFileSystem);
		when(relativeCryptoPath.isAbsolute()).thenReturn(false);
		when(relativeCryptoPath.getFileSystem()).thenReturn(cryptoFileSystem);
		when(cryptoFileSystem.provider()).thenReturn(inTest);

		when(otherPath.isAbsolute()).thenReturn(true);
		when(otherPath.getFileSystem()).thenReturn(otherFileSystem);
		when(otherFileSystem.provider()).thenReturn(otherProvider);
	}

	@ParameterizedTest
	@MethodSource("shouldFailWithProviderMismatch")
	public void testInvocationsWithPathFromOtherProviderFailWithProviderMismatchException(InvocationWhichShouldFail shouldFailWithProviderMismatch) {
		Assertions.assertThrows(ProviderMismatchException.class, () -> {
			shouldFailWithProviderMismatch.invoke(inTest, otherPath);
		});
	}

	@ParameterizedTest
	@MethodSource("shouldFailWithRelativePath")
	public void testInvocationsWithRelativePathFailWithIllegalArgumentException(InvocationWhichShouldFail shouldFailWithRelativePath) {
		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, () -> {
			shouldFailWithRelativePath.invoke(inTest, relativeCryptoPath);
		});
		MatcherAssert.assertThat(e.getMessage(), containsString("Path must be absolute"));
	}

	@Test
	@SuppressWarnings("deprecation")
	public void testFileSystemsIsMock() {
		Assertions.assertSame(fileSystems, inTest.getCryptoFileSystems());
	}

	@Test
	public void testGetSchemeReturnsCryptomatorScheme() {
		Assertions.assertSame("cryptomator", inTest.getScheme());
	}

	@Test
	public void testInitializeFailWithNotDirectoryException() {
		FileSystem fs = Jimfs.newFileSystem(Configuration.unix());
		Path pathToVault = fs.getPath("/vaultDir");

		Assertions.assertThrows(NotDirectoryException.class, () -> {
			CryptoFileSystemProvider.initialize(pathToVault, "irrelevant.txt", "asd");
		});
	}

	@Test
	public void testInitialize() throws IOException {
		FileSystem fs = Jimfs.newFileSystem(Configuration.unix());
		Path pathToVault = fs.getPath("/vaultDir");
		Path masterkeyFile = pathToVault.resolve("masterkey.cryptomator");
		Path dataDir = pathToVault.resolve("d");

		Files.createDirectory(pathToVault);
		CryptoFileSystemProvider.initialize(pathToVault, "masterkey.cryptomator", "asd");

		Assertions.assertTrue(Files.isDirectory(dataDir));
		Assertions.assertTrue(Files.isRegularFile(masterkeyFile));
	}

	@Test
	public void testNoImplicitInitialization() throws IOException {
		FileSystem fs = Jimfs.newFileSystem(Configuration.unix());
		Path pathToVault = fs.getPath("/vaultDir");
		Path masterkeyFile = pathToVault.resolve("masterkey.cryptomator");
		Path dataDir = pathToVault.resolve("d");

		Files.createDirectory(pathToVault);
		URI uri = CryptoFileSystemUri.create(pathToVault);

		CryptoFileSystemProperties properties = cryptoFileSystemProperties() //
				.withFlags() //
				.withMasterkeyFilename("masterkey.cryptomator") //
				.withPassphrase("asd") //
				.build();

		NoSuchFileException e = Assertions.assertThrows(NoSuchFileException.class, () -> {
			inTest.newFileSystem(uri, properties);
		});
		MatcherAssert.assertThat(e.getMessage(), containsString("Vault not initialized"));
		Assertions.assertTrue(Files.notExists(dataDir));
		Assertions.assertTrue(Files.notExists(masterkeyFile));
	}

	@Test
	@SuppressWarnings("deprecation")
	public void testImplicitInitialization() throws IOException {
		FileSystem fs = Jimfs.newFileSystem(Configuration.unix());
		Path pathToVault = fs.getPath("/vaultDir");
		Path masterkeyFile = pathToVault.resolve("masterkey.cryptomator");
		Path dataDir = pathToVault.resolve("d");

		Files.createDirectory(pathToVault);
		URI uri = CryptoFileSystemUri.create(pathToVault);

		CryptoFileSystemProperties properties = cryptoFileSystemProperties() //
				.withFlags(FileSystemFlags.INIT_IMPLICITLY) //
				.withMasterkeyFilename("masterkey.cryptomator") //
				.withPassphrase("asd") //
				.build();
		when(fileSystems.create(eq(inTest), eq(pathToVault), eq(properties))).thenReturn(cryptoFileSystem);
		FileSystem result = inTest.newFileSystem(uri, properties);
		verify(fileSystems).create(eq(inTest), eq(pathToVault), eq(properties));

		Assertions.assertSame(cryptoFileSystem, result);
		Assertions.assertTrue(Files.isDirectory(dataDir));
		Assertions.assertTrue(Files.isRegularFile(masterkeyFile));
	}

	@Test
	public void testContainsVaultReturnsTrueIfDirectoryContainsMasterkeyFileAndDataDir() throws IOException {
		FileSystem fs = Jimfs.newFileSystem(Configuration.unix());

		String masterkeyFilename = "masterkey.foo.baz";
		Path pathToVault = fs.getPath("/vaultDir");

		Path masterkeyFile = pathToVault.resolve(masterkeyFilename);
		Path dataDir = pathToVault.resolve("d");
		Files.createDirectories(dataDir);
		Files.write(masterkeyFile, new byte[0]);

		Assertions.assertTrue(containsVault(pathToVault, masterkeyFilename));
	}

	@Test
	public void testContainsVaultReturnsFalseIfDirectoryContainsNoMasterkeyFileButDataDir() throws IOException {
		FileSystem fs = Jimfs.newFileSystem(Configuration.unix());

		String masterkeyFilename = "masterkey.foo.baz";
		Path pathToVault = fs.getPath("/vaultDir");

		Path dataDir = pathToVault.resolve("d");
		Files.createDirectories(dataDir);

		Assertions.assertFalse(containsVault(pathToVault, masterkeyFilename));
	}

	@Test
	public void testContainsVaultReturnsFalseIfDirectoryContainsMasterkeyFileButNoDataDir() throws IOException {
		FileSystem fs = Jimfs.newFileSystem(Configuration.unix());

		String masterkeyFilename = "masterkey.foo.baz";
		Path pathToVault = fs.getPath("/vaultDir");

		Path masterkeyFile = pathToVault.resolve(masterkeyFilename);
		Files.createDirectories(pathToVault);
		Files.write(masterkeyFile, new byte[0]);

		Assertions.assertFalse(containsVault(pathToVault, masterkeyFilename));
	}

	@Test
	public void testVaultWithChangedPassphraseCanBeOpenedWithNewPassphrase() throws IOException {
		String oldPassphrase = "oldPassphrase838283";
		String newPassphrase = "newPassphrase954810921";
		String masterkeyFilename = "masterkey.foo.baz";
		FileSystem fs = Jimfs.newFileSystem(Configuration.unix());
		Path pathToVault = fs.getPath("/vaultDir");
		Files.createDirectory(pathToVault);
		newFileSystem( //
				pathToVault, //
				cryptoFileSystemProperties() //
						.withMasterkeyFilename(masterkeyFilename) //
						.withPassphrase(oldPassphrase) //
						.build()).close();

		CryptoFileSystemProvider.changePassphrase(pathToVault, masterkeyFilename, oldPassphrase, newPassphrase);

		newFileSystem( //
				pathToVault, //
				cryptoFileSystemProperties() //
						.withMasterkeyFilename(masterkeyFilename) //
						.withPassphrase(newPassphrase) //
						.build()).close();
	}

	@Test
	public void testVaultWithChangedPassphraseCanNotBeOpenedWithOldPassphrase() throws IOException {
		String oldPassphrase = "oldPassphrase838283";
		String newPassphrase = "newPassphrase954810921";
		String masterkeyFilename = "masterkey.foo.baz";
		FileSystem fs = Jimfs.newFileSystem(Configuration.unix());
		Path pathToVault = fs.getPath("/vaultDir");
		Files.createDirectory(pathToVault);
		newFileSystem( //
				pathToVault, //
				cryptoFileSystemProperties() //
						.withMasterkeyFilename(masterkeyFilename) //
						.withPassphrase(oldPassphrase) //
						.build()).close();

		CryptoFileSystemProvider.changePassphrase(pathToVault, masterkeyFilename, oldPassphrase, newPassphrase);

		Assertions.assertThrows(InvalidPassphraseException.class, () -> {
			newFileSystem( //
					pathToVault, //
					cryptoFileSystemProperties() //
							.withMasterkeyFilename(masterkeyFilename) //
							.withPassphrase(oldPassphrase) //
							.build());
		});
	}

	@Test
	public void testGetFileSystemInvokesFileSystemsGetWithPathToVaultFromUri() {
		Path pathToVault = get("a").toAbsolutePath();
		URI uri = CryptoFileSystemUri.create(pathToVault);
		when(fileSystems.get(pathToVault)).thenReturn(cryptoFileSystem);

		FileSystem result = inTest.getFileSystem(uri);

		Assertions.assertSame(cryptoFileSystem, result);
	}

	@Test
	public void testGetPathDelegatesToFileSystem() {
		Path pathToVault = get("a").toAbsolutePath();
		URI uri = CryptoFileSystemUri.create(pathToVault, "c", "d");
		when(fileSystems.get(pathToVault)).thenReturn(cryptoFileSystem);
		when(cryptoFileSystem.getPath("/c/d")).thenReturn(cryptoPath);

		Path result = inTest.getPath(uri);

		Assertions.assertSame(cryptoPath, result);
	}

	@Test
	public void testNewAsyncFileChannelFailsIfOptionsContainAppend() {
		Path irrelevantPath = null;
		ExecutorService irrelevantExecutor = null;

		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			inTest.newAsynchronousFileChannel(irrelevantPath, new HashSet<>(asList(APPEND)), irrelevantExecutor);
		});
	}

	@Test
	@SuppressWarnings("deprecation")
	public void testNewAsyncFileChannelReturnsAsyncDelegatingFileChannelWithNewFileChannelAndExecutor() throws IOException {
		@SuppressWarnings("unchecked")
		Set<OpenOption> options = mock(Set.class);
		ExecutorService executor = mock(ExecutorService.class);
		FileChannel channel = mock(FileChannel.class);
		when(cryptoFileSystem.newFileChannel(cryptoPath, options)).thenReturn(channel);

		AsynchronousFileChannel result = inTest.newAsynchronousFileChannel(cryptoPath, options, executor);

		MatcherAssert.assertThat(result, is(instanceOf(AsyncDelegatingFileChannel.class)));
		AsyncDelegatingFileChannel asyncDelegatingFileChannel = (AsyncDelegatingFileChannel) result;
		Assertions.assertSame(channel, asyncDelegatingFileChannel.getChannel());
		Assertions.assertSame(executor, asyncDelegatingFileChannel.getExecutor());
	}

	@Test
	public void testNewFileChannelDelegatesToFileSystem() throws IOException {
		@SuppressWarnings("unchecked")
		Set<OpenOption> options = mock(Set.class);
		FileChannel channel = mock(FileChannel.class);
		when(cryptoFileSystem.newFileChannel(cryptoPath, options)).thenReturn(channel);

		FileChannel result = inTest.newFileChannel(cryptoPath, options);

		Assertions.assertSame(channel, result);
	}

	@Test
	public void testNewByteChannelDelegatesToFileSystem() throws IOException {
		@SuppressWarnings("unchecked")
		Set<OpenOption> options = mock(Set.class);
		FileChannel channel = mock(FileChannel.class);
		when(cryptoFileSystem.newFileChannel(cryptoPath, options)).thenReturn(channel);

		ByteChannel result = inTest.newByteChannel(cryptoPath, options);

		Assertions.assertSame(channel, result);
	}

	@Test
	public void testNewDirectoryStreamDelegatesToFileSystem() throws IOException {
		@SuppressWarnings("unchecked")
		DirectoryStream<Path> stream = mock(DirectoryStream.class);
		@SuppressWarnings("unchecked")
		Filter<Path> filter = mock(Filter.class);
		when(cryptoFileSystem.newDirectoryStream(cryptoPath, filter)).thenReturn(stream);

		DirectoryStream<Path> result = inTest.newDirectoryStream(cryptoPath, filter);

		Assertions.assertSame(stream, result);
	}

	@Test
	public void testCreateDirectoryDelegatesToFileSystem() throws IOException {
		@SuppressWarnings("unchecked")
		FileAttribute<String> attr = mock(FileAttribute.class);

		inTest.createDirectory(cryptoPath, attr);

		verify(cryptoFileSystem).createDirectory(cryptoPath, attr);
	}

	@Test
	public void testDeleteDelegatesToFileSystem() throws IOException {
		inTest.delete(cryptoPath);

		verify(cryptoFileSystem).delete(cryptoPath);
	}

	@Test
	public void testCopyDelegatesToCopyOperation() throws IOException {
		CopyOption option = mock(CopyOption.class);

		inTest.copy(cryptoPath, secondCryptoPath, option);

		verify(copyOperation).copy(cryptoPath, secondCryptoPath, option);
	}

	@Test
	public void testMoveDelegatesToMoveOperation() throws IOException {
		CopyOption option = mock(CopyOption.class);

		inTest.move(cryptoPath, secondCryptoPath, option);

		verify(moveOperation).move(cryptoPath, secondCryptoPath, option);
	}

	@Test
	public void testIsSameFileReturnsFalseIfFileSystemsOfPathsDoNotMatch() throws IOException {
		Assertions.assertFalse(inTest.isSameFile(cryptoPath, otherPath));
	}

	@Test
	public void testIsSameFileReturnsFalseIfRealPathsOfTwoPathsAreNotEqual() throws IOException {
		when(cryptoPath.toRealPath()).thenReturn(cryptoPath);
		when(secondCryptoPath.toRealPath()).thenReturn(secondCryptoPath);

		Assertions.assertFalse(inTest.isSameFile(cryptoPath, secondCryptoPath));
	}

	@Test
	public void testIsSameFileReturnsTureIfRealPathsOfTwoPathsAreEqual() throws IOException {
		when(cryptoPath.toRealPath()).thenReturn(cryptoPath);
		when(secondCryptoPath.toRealPath()).thenReturn(cryptoPath);

		Assertions.assertTrue(inTest.isSameFile(cryptoPath, secondCryptoPath));
	}

	@Test
	public void testIsHiddenDelegatesToFileSystemIfTrue() throws IOException {
		when(cryptoFileSystem.isHidden(cryptoPath)).thenReturn(true);

		Assertions.assertTrue(inTest.isHidden(cryptoPath));
	}

	@Test
	public void testIsHiddenDelegatesToFileSystemIfFalse() throws IOException {
		when(cryptoFileSystem.isHidden(cryptoPath)).thenReturn(false);

		Assertions.assertFalse(inTest.isHidden(cryptoPath));
	}

	@Test
	public void testCheckAccessDelegatesToFileSystem() throws IOException {
		AccessMode mode = AccessMode.EXECUTE;

		inTest.checkAccess(cryptoPath, mode);

		verify(cryptoFileSystem).checkAccess(cryptoPath, mode);
	}

	@Test
	public void testGetFileStoreDelegatesToFileSystem() throws IOException {
		CryptoFileStore fileStore = mock(CryptoFileStore.class);
		when(cryptoFileSystem.getFileStore()).thenReturn(fileStore);

		FileStore result = inTest.getFileStore(cryptoPath);

		Assertions.assertSame(fileStore, result);
	}

	@Test
	public void testGetFileAttributeViewDelegatesToFileSystem() {
		FileAttributeView view = mock(FileAttributeView.class);
		LinkOption option = LinkOption.NOFOLLOW_LINKS;
		when(cryptoFileSystem.getFileAttributeView(cryptoPath, FileAttributeView.class, option)).thenReturn(view);

		FileAttributeView result = inTest.getFileAttributeView(cryptoPath, FileAttributeView.class, option);

		Assertions.assertSame(view, result);
	}

	@Test
	public void testReadAttributesWithTypeDelegatesToFileSystem() throws IOException {
		BasicFileAttributes attributes = mock(BasicFileAttributes.class);
		LinkOption option = LinkOption.NOFOLLOW_LINKS;
		when(cryptoFileSystem.readAttributes(cryptoPath, BasicFileAttributes.class, option)).thenReturn(attributes);

		BasicFileAttributes result = inTest.readAttributes(cryptoPath, BasicFileAttributes.class, option);

		Assertions.assertSame(attributes, result);
	}

	@Test
	public void testReadAttributesWithNameDelegatesToFileSystem() throws IOException {
		@SuppressWarnings("unchecked")
		Map<String, Object> attributes = mock(Map.class);
		LinkOption option = LinkOption.NOFOLLOW_LINKS;
		String name = "foobar";
		when(cryptoFileSystem.readAttributes(cryptoPath, name, option)).thenReturn(attributes);

		Map<String, Object> result = inTest.readAttributes(cryptoPath, name, option);

		Assertions.assertSame(attributes, result);
	}

	@Test
	public void testSetAttributeDelegatesToFileSystem() throws IOException {
		LinkOption option = LinkOption.NOFOLLOW_LINKS;
		String attribute = "foo";
		String value = "bar";

		inTest.setAttribute(cryptoPath, attribute, value, option);

		verify(cryptoFileSystem).setAttribute(cryptoPath, attribute, value, option);
	}

	private static InvocationWhichShouldFail invocation(String name, Invocation invocation) {
		return new InvocationWhichShouldFail(name, invocation);
	}

	private static class InvocationWhichShouldFail {

		private final String name;
		private final Invocation invocation;

		public InvocationWhichShouldFail(String name, Invocation invocation) {
			this.name = name;
			this.invocation = invocation;
		}

		public void invoke(CryptoFileSystemProvider inTest, Path otherPath) throws IOException {
			invocation.invoke(inTest, otherPath);
		}

		@Override
		public String toString() {
			return name;
		}

	}

	@FunctionalInterface
	private interface Invocation {

		void invoke(CryptoFileSystemProvider inTest, Path otherPath) throws IOException;

	}

}
