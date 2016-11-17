/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.CryptoFileSystemUris.createUri;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.ProviderMismatchException;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;

import org.cryptomator.cryptofs.CryptoFileSystemUris.ParsedUri;
import org.cryptomator.cryptolib.common.SecureRandomModule;

/**
 * <p>
 * A {@link FileSystemProvider} for CryptoFileSystems.
 * <p>
 * A CryptoFileSystem encrypts/decrypts data read/stored from/to it and uses a storage location for the encrypted data. The storage location is denoted by a {@link Path} and can thus be any location
 * itself accessbile via a java.nio.FileSystem.
 * <p>
 * A CryptoFileSystem can be used as any other java.nio.FileSystem, e.g. by using the operations from {@link Files}.
 * <p>
 * <b>Usage</b>
 * 
 * We recommend to use {@link CryptoFileSystemProvider#newFileSystem(Path, CryptoFileSystemProperties)} to create a CryptoFileSystem. To do this:
 * 
 * <blockquote>
 * 
 * <pre>
 * Path storageLocation = Paths.get("/home/cryptobot/vault");
 * FileSystem fileSystem = CryptoFileSystemProvider.newFileSystem(
 * 	storageLocation,
 * 	{@link CryptoFileSystemProperties cryptoFileSystemProperties()}
 * 		.withPassword("password")
 * 		.withReadonlyFlag().build());
 * </pre>
 * 
 * </blockquote>
 * 
 * Afterwards you can use the created {@code FileSystem} to create paths, do directory listings, create files and so on.
 * 
 * <p>
 * To create a new FileSystem from a URI using {@link FileSystems#newFileSystem(URI, Map)} you may have a look at {@link CryptoFileSystemUris}.
 * 
 * @see CryptoFileSystemUris
 * @see CryptoFileSystemProperties
 * @see FileSystems
 * @see FileSystem
 */
public class CryptoFileSystemProvider extends FileSystemProvider {

	private final CryptoFileSystems fileSystems;
	private final CopyAndMoveOperations copyAndMoveOperations;

	public static FileSystem newFileSystem(Path pathToVault, CryptoFileSystemProperties properties) throws IOException {
		return FileSystems.newFileSystem(createUri(pathToVault.toAbsolutePath()), properties);
	}

	public CryptoFileSystemProvider() {
		CryptoFileSystemProviderComponent component = DaggerCryptoFileSystemProviderComponent.builder() //
				.secureRandomModule(new SecureRandomModule(strongSecureRandom())) //
				.cryptoFileSystemProviderModule(CryptoFileSystemProviderModule.builder() //
						.withCrytpoFileSystemProvider(this) //
						.build()) //
				.build();
		this.fileSystems = component.fileSystems();
		this.copyAndMoveOperations = component.copyAndMoveOperations();
	}

	private static SecureRandom strongSecureRandom() {
		try {
			return SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("A strong algorithm must exist in every Java platform.", e);
		}
	}

	/**
	 * @deprecated only for testing
	 */
	@Deprecated
	CryptoFileSystemProvider(CryptoFileSystemProviderComponent component) {
		this.fileSystems = component.fileSystems();
		this.copyAndMoveOperations = component.copyAndMoveOperations();
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
		return CryptoFileSystemUris.URI_SCHEME;
	}

	@Override
	public CryptoFileSystem newFileSystem(URI uri, Map<String, ?> rawProperties) throws IOException {
		ParsedUri parsedUri = CryptoFileSystemUris.parseUri(uri);
		CryptoFileSystemProperties properties = CryptoFileSystemProperties.wrap(rawProperties);
		return fileSystems.create(parsedUri.pathToVault(), properties);
	}

	@Override
	public CryptoFileSystem getFileSystem(URI uri) {
		ParsedUri parsedUri = CryptoFileSystemUris.parseUri(uri);
		return fileSystems.get(parsedUri.pathToVault());
	}

	@Override
	public Path getPath(URI uri) {
		ParsedUri parsedUri = CryptoFileSystemUris.parseUri(uri);
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
		return fileSystem(cleartextPath).newFileChannel(CryptoPath.cast(cleartextPath), optionsSet, attrs);
	}

	@Override
	public SeekableByteChannel newByteChannel(Path cleartextPath, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
		return newFileChannel(cleartextPath, options, attrs);
	}

	@Override
	public DirectoryStream<Path> newDirectoryStream(Path cleartextDir, Filter<? super Path> filter) throws IOException {
		return fileSystem(cleartextDir).newDirectoryStream(CryptoPath.cast(cleartextDir), filter);
	}

	@Override
	public void createDirectory(Path cleartextDir, FileAttribute<?>... attrs) throws IOException {
		fileSystem(cleartextDir).createDirectory(CryptoPath.cast(cleartextDir), attrs);
	}

	@Override
	public void delete(Path cleartextPath) throws IOException {
		fileSystem(cleartextPath).delete(CryptoPath.cast(cleartextPath));
	}

	@Override
	public void copy(Path cleartextSource, Path cleartextTarget, CopyOption... options) throws IOException {
		copyAndMoveOperations.copy(CryptoPath.cast(cleartextSource), CryptoPath.cast(cleartextTarget), options);
	}

	@Override
	public void move(Path cleartextSource, Path cleartextTarget, CopyOption... options) throws IOException {
		copyAndMoveOperations.move(CryptoPath.cast(cleartextSource), CryptoPath.cast(cleartextTarget), options);
	}

	@Override
	public boolean isSameFile(Path cleartextPath, Path cleartextPath2) throws IOException {
		return cleartextPath.getFileSystem() == cleartextPath2.getFileSystem() //
				&& cleartextPath.toRealPath().equals(cleartextPath2.toRealPath());
	}

	@Override
	public boolean isHidden(Path cleartextPath) throws IOException {
		return fileSystem(cleartextPath).isHidden(CryptoPath.cast(cleartextPath));
	}

	@Override
	public FileStore getFileStore(Path cleartextPath) throws IOException {
		return fileSystem(cleartextPath).getFileStore();
	}

	@Override
	public void checkAccess(Path cleartextPath, AccessMode... modes) throws IOException {
		fileSystem(cleartextPath).checkAccess(CryptoPath.cast(cleartextPath), modes);
	}

	@Override
	public <V extends FileAttributeView> V getFileAttributeView(Path cleartextPath, Class<V> type, LinkOption... options) {
		return fileSystem(cleartextPath).getFileAttributeView(CryptoPath.cast(cleartextPath), type, options);
	}

	@Override
	public <A extends BasicFileAttributes> A readAttributes(Path cleartextPath, Class<A> type, LinkOption... options) throws IOException {
		return fileSystem(cleartextPath).readAttributes(CryptoPath.cast(cleartextPath), type, options);
	}

	@Override
	public Map<String, Object> readAttributes(Path cleartextPath, String attributes, LinkOption... options) throws IOException {
		return fileSystem(cleartextPath).readAttributes(CryptoPath.cast(cleartextPath), attributes, options);
	}

	@Override
	public void setAttribute(Path cleartextPath, String attribute, Object value, LinkOption... options) throws IOException {
		fileSystem(cleartextPath).setAttribute(CryptoPath.cast(cleartextPath), attribute, value, options);
	}

	private CryptoFileSystem fileSystem(Path path) {
		FileSystem fileSystem = path.getFileSystem();
		if (fileSystem.provider() == this) {
			CryptoFileSystem cryptoFileSystem = (CryptoFileSystem) fileSystem;
			cryptoFileSystem.assertOpen();
			return cryptoFileSystem;
		} else {
			throw new ProviderMismatchException("Used a path from provider " + fileSystem.provider() + " with provider " + this);
		}
	}

}
