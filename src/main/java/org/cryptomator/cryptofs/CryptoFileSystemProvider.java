/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.exists;
import static org.cryptomator.cryptofs.Constants.DIR_PREFIX;
import static org.cryptomator.cryptofs.Constants.NAME_SHORTENING_THRESHOLD;
import static org.cryptomator.cryptofs.CryptoFileSystemUris.createUri;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.spi.FileSystemProvider;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;

import org.cryptomator.cryptofs.CryptoFileSystemUris.ParsedUri;
import org.cryptomator.cryptofs.CryptoPathMapper.Directory;
import org.cryptomator.cryptolib.common.ReseedingSecureRandom;
import org.cryptomator.cryptolib.v1.CryptorProviderImpl;

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
 * <blockquote><pre>
 * Path storageLocation = Paths.get("/home/cryptobot/vault");
 * FileSystem fileSystem = CryptoFileSystemProvider.newFileSystem(
 * 	storageLocation,
 * 	{@link CryptoFileSystemProperties cryptoFileSystemProperties()}
 * 		.withPassword("password")
 * 		.withReadonlyFlag().build());
 * </pre></blockquote>
 * 
 * Afterwards you can use the created {@code FileSystem} to create paths, do directory listings, create files and so on.
 * 
 * <p>To create a new FileSystem from a URI using {@link FileSystems#newFileSystem(URI, Map)} you may have a look at {@link CryptoFileSystemUris}.
 *  
 * @see {@link CryptoFileSystemUris}, {@link CryptoFileSystemProperties}, {@link FileSystems}, {@link FileSystem}
 */
public class CryptoFileSystemProvider extends FileSystemProvider {

	private final CryptorProviderImpl cryptorProvider;
	private final ConcurrentHashMap<Path, CryptoFileSystem> fileSystems = new ConcurrentHashMap<>();

	public CryptoFileSystemProvider(SecureRandom csprng) {
		this.cryptorProvider = new CryptorProviderImpl(csprng);
	}

	public CryptoFileSystemProvider() {
		this(defaultCsprng());
	}

	private static SecureRandom defaultCsprng() {
		try {
			return new ReseedingSecureRandom(SecureRandom.getInstanceStrong(), SecureRandom.getInstance("SHA1PRNG"), 1 << 30, 55);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Java platform is required to support used instances.", e);
		}
	}

	public static FileSystem newFileSystem(Path pathToVault, CryptoFileSystemProperties properties) throws IOException {
		return FileSystems.newFileSystem(createUri(pathToVault.toAbsolutePath()), properties);
	}

	@Override
	public String getScheme() {
		return CryptoFileSystemUris.URI_SCHEME;
	}

	ConcurrentHashMap<Path, CryptoFileSystem> getFileSystems() {
		return fileSystems;
	}

	@Override
	public FileSystem newFileSystem(URI uri, Map<String, ?> rawProperties) throws IOException {
		ParsedUri parsedUri = CryptoFileSystemUris.parseUri(uri);
		CryptoFileSystemProperties properties = CryptoFileSystemProperties.wrap(rawProperties);
		try {
			return getFileSystems().compute(parsedUri.pathToVault(), (key, value) -> {
				if (value == null) {
					try {
						return new CryptoFileSystem(this, cryptorProvider, key, properties.passphrase(), properties.readonly());
					} catch (IOException e) {
						// TODO use specific wrapper
						throw new UncheckedIOException(e);
					}
				} else {
					throw new FileSystemAlreadyExistsException();
				}
			});
		} catch (UncheckedIOException e) {
			throw e.getCause();
		}
	}

	@Override
	public CryptoFileSystem getFileSystem(URI uri) {
		ParsedUri parsedUri = CryptoFileSystemUris.parseUri(uri);
		return getFileSystem(parsedUri);
	}

	@Override
	public Path getPath(URI uri) {
		ParsedUri parsedUri = CryptoFileSystemUris.parseUri(uri);
		return getFileSystem(parsedUri).getPath(parsedUri.pathInsideVault());
	}

	private CryptoFileSystem getFileSystem(ParsedUri parsedUri) {
		return getFileSystems().computeIfAbsent(parsedUri.pathToVault(), key -> {
			throw new FileSystemNotFoundException();
		});
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
		EffectiveOpenOptions options = EffectiveOpenOptions.from(optionsSet);
		CryptoFileSystem fs = CryptoFileSystem.cast(cleartextPath.getFileSystem());
		Path ciphertextPath = fs.getCryptoPathMapper().getCiphertextFilePath(cleartextPath);
		OpenCryptoFile openCryptoFile = fs.getOpenCryptoFiles().get(ciphertextPath, fs.getCryptor(), options);
		return new CryptoFileChannel(openCryptoFile, options);
	}

	@Override
	public SeekableByteChannel newByteChannel(Path cleartextPath, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
		return newFileChannel(cleartextPath, options, attrs);
	}

	@Override
	public DirectoryStream<Path> newDirectoryStream(Path cleartextDir, Filter<? super Path> filter) throws IOException {
		CryptoFileSystem fs = CryptoFileSystem.cast(cleartextDir.getFileSystem());
		Directory ciphertextDir = fs.getCryptoPathMapper().getCiphertextDir(cleartextDir);
		return new CryptoDirectoryStream(ciphertextDir, cleartextDir, fs.getCryptor().fileNameCryptor(), fs.getLongFileNameProvider(), filter);
	}

	@Override
	public void createDirectory(Path cleartextDir, FileAttribute<?>... attrs) throws IOException {
		CryptoFileSystem fs = CryptoFileSystem.cast(cleartextDir.getFileSystem());
		Path cleartextParentDir = cleartextDir.getParent();
		if (cleartextParentDir == null) {
			return;
		}
		Directory ciphertextParentDir = fs.getCryptoPathMapper().getCiphertextDir(cleartextParentDir);
		if (!exists(ciphertextParentDir.path)) {
			throw new NoSuchFileException(cleartextParentDir.toString());
		}
		String cleartextDirName = cleartextDir.getFileName().toString();
		String ciphertextName = fs.getCryptor().fileNameCryptor().encryptFilename(cleartextDirName, ciphertextParentDir.dirId.getBytes(UTF_8));
		if (exists(ciphertextParentDir.path.resolve(ciphertextName))) {
			throw new FileAlreadyExistsException(cleartextDir.toString());
		}
		String ciphertextDirName = DIR_PREFIX + ciphertextName;
		if (ciphertextDirName.length() >= NAME_SHORTENING_THRESHOLD) {
			ciphertextDirName = fs.getLongFileNameProvider().deflate(ciphertextDirName);
		}
		Path dirFile = ciphertextParentDir.path.resolve(ciphertextDirName);
		Directory ciphertextDir = fs.getCryptoPathMapper().getCiphertextDir(cleartextDir);
		try (FileChannel channel = FileChannel.open(dirFile, EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), attrs)) {
			channel.write(ByteBuffer.wrap(ciphertextDir.dirId.getBytes(UTF_8)));
		}
		boolean success = false;
		try {
			Files.createDirectories(ciphertextDir.path);
			success = true;
		} finally {
			if (!success) {
				Files.delete(dirFile);
			}
		}
	}

	@Override
	public void delete(Path cleartextPath) throws IOException {
		// TODO Auto-generated method stub

	}

	@Override
	public void copy(Path cleartextSource, Path cleartextTarget, CopyOption... options) throws IOException {
		// TODO Auto-generated method stub

	}

	@Override
	public void move(Path cleartextSource, Path cleartextTarget, CopyOption... options) throws IOException {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean isSameFile(Path cleartextPath, Path cleartextPath2) throws IOException {
		return cleartextPath.equals(cleartextPath2);
	}

	@Override
	public boolean isHidden(Path cleartextPath) throws IOException {
		FileStore store = getFileStore(cleartextPath);
		if (store.supportsFileAttributeView(DosFileAttributeView.class)) {
			DosFileAttributeView view = this.getFileAttributeView(cleartextPath, DosFileAttributeView.class);
			return view.readAttributes().isHidden();
		} else {
			return false;
		}
	}

	@Override
	public FileStore getFileStore(Path cleartextPath) throws IOException {
		return BasicPath.cast(cleartextPath).getFileSystem().getFileStore();
	}

	@Override
	public void checkAccess(Path cleartextPath, AccessMode... modes) throws IOException {
		FileStore store = getFileStore(cleartextPath);
		if (store.supportsFileAttributeView(PosixFileAttributeView.class)) {
			Set<PosixFilePermission> permissions = readAttributes(cleartextPath, PosixFileAttributes.class).permissions();
			boolean accessGranted = true;
			for (AccessMode accessMode : modes) {
				switch (accessMode) {
				case READ:
					accessGranted &= permissions.contains(PosixFilePermission.OWNER_READ);
					break;
				case WRITE:
					accessGranted &= permissions.contains(PosixFilePermission.OWNER_WRITE);
					break;
				case EXECUTE:
					accessGranted &= permissions.contains(PosixFilePermission.OWNER_EXECUTE);
					break;
				default:
					throw new UnsupportedOperationException("AccessMode " + accessMode + " not supported.");
				}
			}
			if (!accessGranted) {
				throw new AccessDeniedException(cleartextPath.toString());
			}
		} else {
			// read attributes to check for file existence / throws IOException if file does not exist
			readAttributes(cleartextPath, BasicFileAttributes.class);
		}
	}

	@Override
	public <V extends FileAttributeView> V getFileAttributeView(Path cleartextPath, Class<V> type, LinkOption... options) {
		// TODO wrap FileAttributeView und so
		try {
			CryptoFileSystem fs = CryptoFileSystem.cast(cleartextPath.getFileSystem());
			Path ciphertextDirPath = fs.getCryptoPathMapper().getCiphertextDirPath(cleartextPath);
			if (Files.notExists(ciphertextDirPath) && cleartextPath.getNameCount() > 0) {
				Path ciphertextFilePath = fs.getCryptoPathMapper().getCiphertextFilePath(cleartextPath);
				return Files.getFileAttributeView(ciphertextFilePath, type);
			} else {
				return Files.getFileAttributeView(ciphertextDirPath, type);
			}
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	@Override
	public <A extends BasicFileAttributes> A readAttributes(Path cleartextPath, Class<A> type, LinkOption... options) throws IOException {
		// TODO wrap FileAttribute und so
		CryptoFileSystem fs = CryptoFileSystem.cast(cleartextPath.getFileSystem());
		Path ciphertextDirPath = fs.getCryptoPathMapper().getCiphertextDirPath(cleartextPath);
		if (Files.notExists(ciphertextDirPath) && cleartextPath.getNameCount() > 0) {
			Path ciphertextFilePath = fs.getCryptoPathMapper().getCiphertextFilePath(cleartextPath);
			return fs.getFileAttributeProvider().readAttributes(ciphertextFilePath, type);
		} else {
			return fs.getFileAttributeProvider().readAttributes(ciphertextDirPath, type);
		}
	}

	@Override
	public Map<String, Object> readAttributes(Path cleartextPath, String attributes, LinkOption... options) throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setAttribute(Path cleartextPath, String attribute, Object value, LinkOption... options) throws IOException {
		// TODO Auto-generated method stub

	}

}
