package org.cryptomator.cryptofs;

import static java.nio.file.Paths.get;
import static java.nio.file.StandardOpenOption.APPEND;
import static java.util.Arrays.asList;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.cryptomator.cryptofs.CryptoFileSystemProvider.containsVault;
import static org.cryptomator.cryptofs.CryptoFileSystemProvider.newFileSystem;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
import java.nio.file.NotDirectoryException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.ProviderMismatchException;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;

import org.cryptomator.cryptofs.CryptoFileSystemProperties.FileSystemFlags;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

@RunWith(Theories.class)
public class CryptoFileSystemProviderTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

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

	@DataPoints("shouldFailWithProviderMismatch")
	@SuppressWarnings("unchecked")
	public static final List<InvocationWhichShouldFail> INVOCATIONS_FAILING_WITH_PROVIDER_MISMATCH = asList( //
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

	@DataPoints("shouldFailWithRelativePath")
	@SuppressWarnings("unchecked")
	public static final List<InvocationWhichShouldFail> INVOCATIONS_FAILING_WITH_RELATIVE_PATH = asList( //
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

	@Before
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

	@Theory
	public void testInvocationsWithPathFromOtherProviderFailWithProviderMismatchException(@FromDataPoints("shouldFailWithProviderMismatch") InvocationWhichShouldFail shouldFailWithProviderMismatch)
			throws IOException {
		thrown.expect(ProviderMismatchException.class);

		shouldFailWithProviderMismatch.invoke(inTest, otherPath);
	}

	@Theory
	public void testInvocationsWithRelativePathFailWithIllegalArgumentException(@FromDataPoints("shouldFailWithRelativePath") InvocationWhichShouldFail shouldFailWithRelativePath) throws IOException {
		thrown.expect(IllegalArgumentException.class);
		thrown.expectMessage("Path must be absolute");

		shouldFailWithRelativePath.invoke(inTest, relativeCryptoPath);
	}

	@Test
	@SuppressWarnings("deprecation")
	public void testFileSystemsIsMock() {
		assertThat(inTest.getCryptoFileSystems(), is(fileSystems));
	}

	@Test
	public void testGetSchemeReturnsCryptomatorScheme() {
		assertThat(inTest.getScheme(), is("cryptomator"));
	}

	@Test(expected = NotDirectoryException.class)
	public void testInitializeFailWithNotDirectoryException() throws IOException {
		FileSystem fs = Jimfs.newFileSystem(Configuration.unix());
		Path pathToVault = fs.getPath("/vaultDir");

		CryptoFileSystemProvider.initialize(pathToVault, "irrelevant.txt", "asd");
	}

	@Test
	public void testInitialize() throws IOException {
		FileSystem fs = Jimfs.newFileSystem(Configuration.unix());
		Path pathToVault = fs.getPath("/vaultDir");
		Path masterkeyFile = pathToVault.resolve("masterkey.cryptomator");
		Path dataDir = pathToVault.resolve("d");

		Files.createDirectory(pathToVault);
		CryptoFileSystemProvider.initialize(pathToVault, "masterkey.cryptomator", "asd");

		Assert.assertTrue(Files.isDirectory(dataDir));
		Assert.assertTrue(Files.isRegularFile(masterkeyFile));
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
		inTest.newFileSystem(uri, properties);
		verify(fileSystems).create(eq(pathToVault), eq(properties));

		Assert.assertTrue(Files.notExists(dataDir));
		Assert.assertTrue(Files.notExists(masterkeyFile));
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
		inTest.newFileSystem(uri, properties);
		verify(fileSystems).create(eq(pathToVault), eq(properties));

		Assert.assertTrue(Files.isDirectory(dataDir));
		Assert.assertTrue(Files.isRegularFile(masterkeyFile));
	}

	@Test
	public void testNewFileSystemInvokesFileSystemsCreate() throws IOException {
		Path pathToVault = get("a").toAbsolutePath();

		URI uri = CryptoFileSystemUri.create(pathToVault);
		CryptoFileSystemProperties properties = cryptoFileSystemProperties().withPassphrase("asd").withFlags().build();
		when(fileSystems.create(eq(pathToVault), eq(properties))).thenReturn(cryptoFileSystem);

		FileSystem result = inTest.newFileSystem(uri, properties);

		assertThat(result, is(cryptoFileSystem));
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

		assertTrue(containsVault(pathToVault, masterkeyFilename));
	}

	@Test
	public void testContainsVaultReturnsFalseIfDirectoryContainsNoMasterkeyFileButDataDir() throws IOException {
		FileSystem fs = Jimfs.newFileSystem(Configuration.unix());

		String masterkeyFilename = "masterkey.foo.baz";
		Path pathToVault = fs.getPath("/vaultDir");

		Path dataDir = pathToVault.resolve("d");
		Files.createDirectories(dataDir);

		assertFalse(containsVault(pathToVault, masterkeyFilename));
	}

	@Test
	public void testContainsVaultReturnsFalseIfDirectoryContainsMasterkeyFileButNoDataDir() throws IOException {
		FileSystem fs = Jimfs.newFileSystem(Configuration.unix());

		String masterkeyFilename = "masterkey.foo.baz";
		Path pathToVault = fs.getPath("/vaultDir");

		Path masterkeyFile = pathToVault.resolve(masterkeyFilename);
		Files.createDirectories(pathToVault);
		Files.write(masterkeyFile, new byte[0]);

		assertFalse(containsVault(pathToVault, masterkeyFilename));
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

		thrown.expect(InvalidPassphraseException.class);

		newFileSystem( //
				pathToVault, //
				cryptoFileSystemProperties() //
						.withMasterkeyFilename(masterkeyFilename) //
						.withPassphrase(oldPassphrase) //
						.build());
	}

	@Test
	public void testGetFileSystemInvokesFileSystemsGetWithPathToVaultFromUri() {
		Path pathToVault = get("a").toAbsolutePath();
		URI uri = CryptoFileSystemUri.create(pathToVault);
		when(fileSystems.get(pathToVault)).thenReturn(cryptoFileSystem);

		FileSystem result = inTest.getFileSystem(uri);

		assertThat(result, is(cryptoFileSystem));
	}

	@Test
	public void testGetPathDelegatesToFileSystem() {
		Path pathToVault = get("a").toAbsolutePath();
		URI uri = CryptoFileSystemUri.create(pathToVault, "c", "d");
		when(fileSystems.get(pathToVault)).thenReturn(cryptoFileSystem);
		when(cryptoFileSystem.getPath("/c/d")).thenReturn(cryptoPath);

		Path result = inTest.getPath(uri);

		assertThat(result, is(cryptoPath));
	}

	@Test
	public void testNewAsyncFileChannelFailsIfOptionsContainAppend() throws IOException {
		Path irrelevantPath = null;
		ExecutorService irrelevantExecutor = null;

		thrown.expect(IllegalArgumentException.class);

		inTest.newAsynchronousFileChannel(irrelevantPath, new HashSet<>(asList(APPEND)), irrelevantExecutor);
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

		assertThat(result, is(instanceOf(AsyncDelegatingFileChannel.class)));
		AsyncDelegatingFileChannel asyncDelegatingFileChannel = (AsyncDelegatingFileChannel) result;
		assertThat(asyncDelegatingFileChannel.getChannel(), is(channel));
		assertThat(asyncDelegatingFileChannel.getExecutor(), is(executor));
	}

	@Test
	public void testNewFileChannelDelegatesToFileSystem() throws IOException {
		@SuppressWarnings("unchecked")
		Set<OpenOption> options = mock(Set.class);
		FileChannel channel = mock(FileChannel.class);
		when(cryptoFileSystem.newFileChannel(cryptoPath, options)).thenReturn(channel);

		FileChannel result = inTest.newFileChannel(cryptoPath, options);

		assertThat(result, is(channel));
	}

	@Test
	public void testNewByteChannelDelegatesToFileSystem() throws IOException {
		@SuppressWarnings("unchecked")
		Set<OpenOption> options = mock(Set.class);
		FileChannel channel = mock(FileChannel.class);
		when(cryptoFileSystem.newFileChannel(cryptoPath, options)).thenReturn(channel);

		ByteChannel result = inTest.newByteChannel(cryptoPath, options);

		assertThat(result, is(channel));
	}

	@Test
	public void testNewDirectoryStreamDelegatesToFileSystem() throws IOException {
		@SuppressWarnings("unchecked")
		DirectoryStream<Path> stream = mock(DirectoryStream.class);
		@SuppressWarnings("unchecked")
		Filter<Path> filter = mock(Filter.class);
		when(cryptoFileSystem.newDirectoryStream(cryptoPath, filter)).thenReturn(stream);

		DirectoryStream<Path> result = inTest.newDirectoryStream(cryptoPath, filter);

		assertThat(result, is(stream));
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
		assertFalse(inTest.isSameFile(cryptoPath, otherPath));
	}

	@Test
	public void testIsSameFileReturnsFalseIfRealPathsOfTwoPathsAreNotEqual() throws IOException {
		when(cryptoPath.toRealPath()).thenReturn(cryptoPath);
		when(secondCryptoPath.toRealPath()).thenReturn(secondCryptoPath);

		assertFalse(inTest.isSameFile(cryptoPath, secondCryptoPath));
	}

	@Test
	public void testIsSameFileReturnsTureIfRealPathsOfTwoPathsAreEqual() throws IOException {
		when(cryptoPath.toRealPath()).thenReturn(cryptoPath);
		when(secondCryptoPath.toRealPath()).thenReturn(cryptoPath);

		assertTrue(inTest.isSameFile(cryptoPath, secondCryptoPath));
	}

	@Test
	public void testIsHiddenDelegatesToFileSystemIfTrue() throws IOException {
		when(cryptoFileSystem.isHidden(cryptoPath)).thenReturn(true);

		assertTrue(inTest.isHidden(cryptoPath));
	}

	@Test
	public void testIsHiddenDelegatesToFileSystemIfFalse() throws IOException {
		when(cryptoFileSystem.isHidden(cryptoPath)).thenReturn(false);

		assertFalse(inTest.isHidden(cryptoPath));
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

		assertThat(result, is(fileStore));
	}

	@Test
	public void testGetFileAttributeViewDelegatesToFileSystem() {
		FileAttributeView view = mock(FileAttributeView.class);
		LinkOption option = LinkOption.NOFOLLOW_LINKS;
		when(cryptoFileSystem.getFileAttributeView(cryptoPath, FileAttributeView.class, option)).thenReturn(view);

		FileAttributeView result = inTest.getFileAttributeView(cryptoPath, FileAttributeView.class, option);

		assertThat(result, is(view));
	}

	@Test
	public void testReadAttributesWithTypeDelegatesToFileSystem() throws IOException {
		BasicFileAttributes attributes = mock(BasicFileAttributes.class);
		LinkOption option = LinkOption.NOFOLLOW_LINKS;
		when(cryptoFileSystem.readAttributes(cryptoPath, BasicFileAttributes.class, option)).thenReturn(attributes);

		BasicFileAttributes result = inTest.readAttributes(cryptoPath, BasicFileAttributes.class, option);

		assertThat(result, is(attributes));
	}

	@Test
	public void testReadAttributesWithNameDelegatesToFileSystem() throws IOException {
		@SuppressWarnings("unchecked")
		Map<String, Object> attributes = mock(Map.class);
		LinkOption option = LinkOption.NOFOLLOW_LINKS;
		String name = "foobar";
		when(cryptoFileSystem.readAttributes(cryptoPath, name, option)).thenReturn(attributes);

		Map<String, Object> result = inTest.readAttributes(cryptoPath, name, option);

		assertThat(result, is(attributes));
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
