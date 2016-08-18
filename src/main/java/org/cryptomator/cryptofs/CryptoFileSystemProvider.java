/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.FileStore;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.FileSystems;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.spi.FileSystemProvider;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;

import org.cryptomator.cryptofs.CryptoPathMapper.Directory;
import org.cryptomator.cryptolib.common.ReseedingSecureRandom;
import org.cryptomator.cryptolib.v1.CryptorProviderImpl;

public class CryptoFileSystemProvider extends FileSystemProvider {

	/**
	 * example: cryptomator://Path/to/vault#/path/inside/vault
	 */
	private static final String URI_SCHEME = "cryptomator";

	/**
	 * Key identifying the passphrase for a encrypted vault.
	 */
	public static final String FS_ENV_PW = "passphrase";

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

	@Override
	public String getScheme() {
		return URI_SCHEME;
	}

	ConcurrentHashMap<Path, CryptoFileSystem> getFileSystems() {
		return fileSystems;
	}

	@Override
	public CryptoFileSystem newFileSystem(URI uri, Map<String, ?> env) throws IOException {
		if (!env.containsKey(FS_ENV_PW) || !(env.get(FS_ENV_PW) instanceof CharSequence)) {
			throw new IllegalArgumentException("Required environment parameter " + FS_ENV_PW + " not specified.");
		}
		CharSequence passphrase = (CharSequence) env.get(FS_ENV_PW);
		Path pathToVault = FileSystems.getDefault().getPath(uri.getPath());
		return getFileSystems().compute(pathToVault, (key, value) -> {
			if (value == null) {
				return new CryptoFileSystem(this, cryptorProvider, key, passphrase);
			} else {
				throw new FileSystemAlreadyExistsException();
			}
		});
	}

	@Override
	public CryptoFileSystem getFileSystem(URI uri) {
		Path pathToVault = FileSystems.getDefault().getPath(uri.getPath());
		return getFileSystems().computeIfAbsent(pathToVault, key -> {
			throw new FileSystemNotFoundException();
		});
	}

	@Override
	public Path getPath(URI uri) {
		return getFileSystem(uri).getPath(uri.getFragment());
	}

	@Override
	public AsynchronousFileChannel newAsynchronousFileChannel(Path cleartextPath, Set<? extends OpenOption> options, ExecutorService executor, FileAttribute<?>... attrs) throws IOException {
		return new AsyncDelegatingFileChannel(newFileChannel(cleartextPath, options, attrs), executor);
	}

	@Override
	public FileChannel newFileChannel(Path cleartextPath, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
		CryptoFileSystem fs = CryptoFileSystem.cast(cleartextPath.getFileSystem());
		Path ciphertextPath = fs.getCryptoPathMapper().getCiphertextFilePath(cleartextPath);
		return new CryptoFileChannel(fs.getCryptor(), ciphertextPath, options);
	}

	@Override
	public SeekableByteChannel newByteChannel(Path cleartextPath, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
		return newFileChannel(cleartextPath, options, attrs);
	}

	@Override
	public DirectoryStream<Path> newDirectoryStream(Path cleartextDir, Filter<? super Path> filter) throws IOException {
		CryptoFileSystem fs = CryptoFileSystem.cast(cleartextDir.getFileSystem());
		Directory ciphertextDir = fs.getCryptoPathMapper().getCiphertextDir(cleartextDir);
		return new CryptoDirectoryStream(ciphertextDir, cleartextDir, fs.getCryptor().fileNameCryptor(), filter);
	}

	@Override
	public void createDirectory(Path dir, FileAttribute<?>... attrs) throws IOException {
		// TODO Auto-generated method stub

	}

	@Override
	public void delete(Path path) throws IOException {
		// TODO Auto-generated method stub

	}

	@Override
	public void copy(Path source, Path target, CopyOption... options) throws IOException {
		// TODO Auto-generated method stub

	}

	@Override
	public void move(Path source, Path target, CopyOption... options) throws IOException {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean isSameFile(Path path, Path path2) throws IOException {
		return path.equals(path2);
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
		// TODO check if file exists first and throw NoSuchFileException, if it doesn't.
		FileStore store = getFileStore(cleartextPath);
		if (store.supportsFileAttributeView(PosixFileAttributeView.class)) {
			PosixFileAttributeView view = this.getFileAttributeView(cleartextPath, PosixFileAttributeView.class);
			Set<PosixFilePermission> permissions = view.readAttributes().permissions();
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
		}
	}

	@Override
	public <V extends FileAttributeView> V getFileAttributeView(Path cleartextPath, Class<V> type, LinkOption... options) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public <A extends BasicFileAttributes> A readAttributes(Path cleartextPath, Class<A> type, LinkOption... options) throws IOException {
		CryptoFileSystem fs = CryptoFileSystem.cast(cleartextPath.getFileSystem());
		Path ciphertextPath = fs.getCryptoPathMapper().getCiphertextFilePath(cleartextPath);
		return fs.getFileAttributeProvider().readAttributes(ciphertextPath, type);
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
