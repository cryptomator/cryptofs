/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.ch.AsyncDelegatingFileChannel;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.FileSystemCapabilityChecker;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NotDirectoryException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.ProviderMismatchException;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;

import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.WRITE;

/**
 * <p>
 * A {@link FileSystemProvider} for {@link CryptoFileSystem CryptoFileSystems}.
 * <p>
 * All {@code FileSystem} instances created by {@link CryptoFileSystemProvider} are instances of {@code CryptoFileSystem}.
 *
 * <b>Usage</b>
 * <p>
 * It is recommended to use {@link CryptoFileSystemProvider#newFileSystem(Path, CryptoFileSystemProperties)} to create a CryptoFileSystem. To do this:
 *
 * <blockquote>
 *
 * <pre>
 * Path storageLocation = Paths.get("/home/cryptobot/vault");
 * FileSystem fileSystem = CryptoFileSystemProvider.newFileSystem(
 * 	storageLocation,
 *    {@link CryptoFileSystemProperties cryptoFileSystemProperties()}
 * 		.withPassword("password")
 * 		.withFlags(FileSystemFlags.READONLY)
 * 		.build());
 * </pre>
 *
 * </blockquote>
 * <p>
 * Afterwards you can use the created {@code FileSystem} to create paths, do directory listings, create files and so on.
 * <p>
 * <p>
 * To create a new FileSystem from a URI using {@link FileSystems#newFileSystem(URI, Map)} you may have a look at {@link CryptoFileSystemUri}.
 *
 * @see CryptoFileSystemUri
 * @see CryptoFileSystemProperties
 * @see FileSystems
 * @see FileSystem
 */
public class CryptoFileSystemProvider extends FileSystemProvider {

	private final CryptoFileSystems fileSystems;
	private final MoveOperation moveOperation;
	private final CopyOperation copyOperation;

	public CryptoFileSystemProvider() {
		this(DaggerCryptoFileSystemProviderComponent.create());
	}

	/**
	 * visible for testing
	 */
	CryptoFileSystemProvider(CryptoFileSystemProviderComponent component) {
		this.fileSystems = component.fileSystems();
		this.moveOperation = component.moveOperation();
		this.copyOperation = component.copyOperation();
	}

	/**
	 * Typesafe alternative to {@link FileSystems#newFileSystem(URI, Map)}. Default way to retrieve a CryptoFS instance.
	 *
	 * @param pathToVault Path to this vault's storage location
	 * @param properties  Parameters used during initialization of the file system
	 * @return a new file system
	 * @throws FileSystemNeedsMigrationException                      if the vault format needs to get updated and <code>properties</code> did not contain a flag for implicit migration.
	 * @throws FileSystemCapabilityChecker.MissingCapabilityException If the underlying filesystem lacks features required to store a vault
	 * @throws IOException                                            if an I/O error occurs creating the file system
	 */
	public static CryptoFileSystem newFileSystem(Path pathToVault, CryptoFileSystemProperties properties) throws FileSystemNeedsMigrationException, IOException {
		URI uri = CryptoFileSystemUri.create(pathToVault.toAbsolutePath());
		return (CryptoFileSystem) FileSystems.newFileSystem(uri, properties);
	}

	/**
	 * Creates a new vault at the given directory path.
	 *
	 * @param pathToVault         Path to an existing directory
	 * @param vaultConfigFilename Name of the vault config file
	 * @param keyId               The ID of the key to associate with this vault
	 * @param keyLoader           A key loader providing the masterkey for this new vault
	 * @throws NotDirectoryException                                  If the given path is not an existing directory.
	 * @throws FileSystemCapabilityChecker.MissingCapabilityException If the underlying filesystem lacks features required to store a vault
	 * @throws IOException                                            If the vault structure could not be initialized due to I/O errors
	 * @since 2.0.0
	 */
	public static void initialize(Path pathToVault, String vaultConfigFilename, String keyId, KeyLoader keyLoader) throws NotDirectoryException, IOException {
		if (!Files.isDirectory(pathToVault)) {
			throw new NotDirectoryException(pathToVault.toString());
		}
		byte[] rawKey = keyLoader.loadKey(keyId);
		try {
			// save vault config:
			Path vaultConfigPath = pathToVault.resolve(vaultConfigFilename);
			var config = VaultConfig.createNew().cipherMode(VaultCipherMode.SIV_CTRMAC).maxFilenameLength(Constants.MAX_CIPHERTEXT_NAME_LENGTH).build();
			var token = config.toToken(keyId, rawKey);
			Files.writeString(vaultConfigPath, token, StandardCharsets.US_ASCII, WRITE, CREATE_NEW);
			// create "d" dir:
			Path dataDirPath = pathToVault.resolve(Constants.DATA_DIR_NAME);
			Files.createDirectories(dataDirPath);
		} finally {
			Arrays.fill(rawKey, (byte) 0x00);
		}
		assert containsVault(pathToVault, vaultConfigFilename);
	}

	/**
	 * Checks if the folder represented by the given path exists and contains a valid vault structure.
	 *
	 * @param pathToVault         A directory path
	 * @param vaultConfigFilename Name of the vault config file
	 * @return <code>true</code> if the directory seems to contain a vault.
	 * @since 2.0.0
	 */
	public static boolean containsVault(Path pathToVault, String vaultConfigFilename) {
		Path vaultConfigPath = pathToVault.resolve(vaultConfigFilename);
		Path dataDirPath = pathToVault.resolve(Constants.DATA_DIR_NAME);
		return Files.isReadable(vaultConfigPath) && Files.isDirectory(dataDirPath);
	}

	/**
	 * @deprecated only for testing
	 */
	@Deprecated
	CryptoFileSystems getCryptoFileSystems() {
		return fileSystems;
	}

	@Override
	public String getScheme() {
		return CryptoFileSystemUri.URI_SCHEME;
	}

	@Override
	public CryptoFileSystem newFileSystem(URI uri, Map<String, ?> rawProperties) throws IOException {
		CryptoFileSystemUri parsedUri = CryptoFileSystemUri.parse(uri);
		CryptoFileSystemProperties properties = CryptoFileSystemProperties.wrap(rawProperties);
		return fileSystems.create(this, parsedUri.pathToVault(), properties);
	}

	@Override
	public CryptoFileSystem getFileSystem(URI uri) {
		CryptoFileSystemUri parsedUri = CryptoFileSystemUri.parse(uri);
		return fileSystems.get(parsedUri.pathToVault());
	}

	@Override
	public Path getPath(URI uri) {
		CryptoFileSystemUri parsedUri = CryptoFileSystemUri.parse(uri);
		return fileSystems.get(parsedUri.pathToVault()).getPath(parsedUri.pathInsideVault());
	}

	@Override
	public AsynchronousFileChannel newAsynchronousFileChannel(Path cleartextPath, Set<? extends OpenOption> options, ExecutorService executor, FileAttribute<?>... attrs) throws IOException {
		if (options.contains(StandardOpenOption.APPEND)) {
			throw new IllegalArgumentException("AsynchronousFileChannel can not be opened in append mode");
		}
		return new AsyncDelegatingFileChannel(newFileChannel(cleartextPath, options, attrs), executor);
	}

	@Override
	public FileChannel newFileChannel(Path cleartextPath, Set<? extends OpenOption> optionsSet, FileAttribute<?>... attrs) throws IOException {
		return fileSystem(cleartextPath).newFileChannel(CryptoPath.castAndAssertAbsolute(cleartextPath), optionsSet, attrs);
	}

	@Override
	public SeekableByteChannel newByteChannel(Path cleartextPath, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
		return newFileChannel(cleartextPath, options, attrs);
	}

	@Override
	public DirectoryStream<Path> newDirectoryStream(Path cleartextDir, Filter<? super Path> filter) throws IOException {
		return fileSystem(cleartextDir).newDirectoryStream(CryptoPath.castAndAssertAbsolute(cleartextDir), filter);
	}

	@Override
	public void createDirectory(Path cleartextDir, FileAttribute<?>... attrs) throws IOException {
		fileSystem(cleartextDir).createDirectory(CryptoPath.castAndAssertAbsolute(cleartextDir), attrs);
	}

	@Override
	public void delete(Path cleartextPath) throws IOException {
		fileSystem(cleartextPath).delete(CryptoPath.castAndAssertAbsolute(cleartextPath));
	}

	@Override
	public void copy(Path cleartextSource, Path cleartextTarget, CopyOption... options) throws IOException {
		assertSameProvider(cleartextSource);
		assertSameProvider(cleartextTarget);
		copyOperation.copy(CryptoPath.castAndAssertAbsolute(cleartextSource), CryptoPath.castAndAssertAbsolute(cleartextTarget), options);
	}

	@Override
	public void move(Path cleartextSource, Path cleartextTarget, CopyOption... options) throws IOException {
		assertSameProvider(cleartextSource);
		assertSameProvider(cleartextTarget);
		moveOperation.move(CryptoPath.castAndAssertAbsolute(cleartextSource), CryptoPath.castAndAssertAbsolute(cleartextTarget), options);
	}

	@Override
	public boolean isSameFile(Path cleartextPath, Path cleartextPath2) throws IOException {
		return cleartextPath.getFileSystem() == cleartextPath2.getFileSystem() //
				&& cleartextPath.toRealPath().equals(cleartextPath2.toRealPath());
	}

	@Override
	public boolean isHidden(Path cleartextPath) throws IOException {
		return fileSystem(cleartextPath).isHidden(CryptoPath.castAndAssertAbsolute(cleartextPath));
	}

	@Override
	public FileStore getFileStore(Path cleartextPath) {
		return fileSystem(cleartextPath).getFileStore();
	}

	@Override
	public void checkAccess(Path cleartextPath, AccessMode... modes) throws IOException {
		fileSystem(cleartextPath).checkAccess(CryptoPath.castAndAssertAbsolute(cleartextPath), modes);
	}

	@Override
	public void createSymbolicLink(Path cleartextPath, Path target, FileAttribute<?>... attrs) throws IOException {
		fileSystem(cleartextPath).createSymbolicLink(CryptoPath.castAndAssertAbsolute(cleartextPath), target, attrs);
	}

	@Override
	public Path readSymbolicLink(Path cleartextPath) throws IOException {
		return fileSystem(cleartextPath).readSymbolicLink(CryptoPath.castAndAssertAbsolute(cleartextPath));
	}

	@Override
	public <V extends FileAttributeView> V getFileAttributeView(Path cleartextPath, Class<V> type, LinkOption... options) {
		return fileSystem(cleartextPath).getFileAttributeView(CryptoPath.castAndAssertAbsolute(cleartextPath), type, options);
	}

	@Override
	public <A extends BasicFileAttributes> A readAttributes(Path cleartextPath, Class<A> type, LinkOption... options) throws IOException {
		return fileSystem(cleartextPath).readAttributes(CryptoPath.castAndAssertAbsolute(cleartextPath), type, options);
	}

	@Override
	public Map<String, Object> readAttributes(Path cleartextPath, String attributes, LinkOption... options) throws IOException {
		return fileSystem(cleartextPath).readAttributes(CryptoPath.castAndAssertAbsolute(cleartextPath), attributes, options);
	}

	@Override
	public void setAttribute(Path cleartextPath, String attribute, Object value, LinkOption... options) throws IOException {
		fileSystem(cleartextPath).setAttribute(CryptoPath.castAndAssertAbsolute(cleartextPath), attribute, value, options);
	}

	private CryptoFileSystemImpl fileSystem(Path path) {
		assertSameProvider(path);
		CryptoFileSystemImpl fs = CryptoPath.cast(path).getFileSystem();
		fs.assertOpen();
		return fs;
	}

	private void assertSameProvider(Path path) {
		if (path.getFileSystem().provider() != this) {
			throw new ProviderMismatchException("Used a path from provider " + path.getFileSystem().provider() + " with provider " + this);
		}
	}

}
