/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cryptomator.cryptofs.Constants.SEPARATOR;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.AccessMode;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.ClosedFileSystemException;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.spi.FileSystemProvider;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;

import org.apache.commons.lang3.ArrayUtils;
import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType;
import org.cryptomator.cryptofs.CryptoPathMapper.Directory;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@PerFileSystem
class CryptoFileSystemImpl extends CryptoFileSystem {

	private static final Logger LOG = LoggerFactory.getLogger(CryptoFileSystemImpl.class);

	private final CryptoPath rootPath;
	private final CryptoPath emptyPath;

	private final CryptoFileSystemProvider provider;
	private final CryptoFileSystems cryptoFileSystems;
	private final Path pathToVault;
	private final Cryptor cryptor;
	private final CryptoPathMapper cryptoPathMapper;
	private final DirectoryIdProvider dirIdProvider;
	private final CryptoFileAttributeProvider fileAttributeProvider;
	private final CryptoFileAttributeByNameProvider fileAttributeByNameProvider;
	private final CryptoFileAttributeViewProvider fileAttributeViewProvider;
	private final DirectoryStreamFactory directoryStreamFactory;
	private final OpenCryptoFiles openCryptoFiles;
	private final CryptoFileStore fileStore;
	private final PathMatcherFactory pathMatcherFactory;
	private final CryptoPathFactory cryptoPathFactory;
	private final CryptoFileSystemStats stats;
	private final FinallyUtil finallyUtil;

	private volatile boolean open = true;

	@Inject
	public CryptoFileSystemImpl(@PathToVault Path pathToVault, CryptoFileSystemProperties properties, Cryptor cryptor, CryptoFileSystemProvider provider, CryptoFileSystems cryptoFileSystems, CryptoFileStore fileStore,
			OpenCryptoFiles openCryptoFiles, CryptoPathMapper cryptoPathMapper, DirectoryIdProvider dirIdProvider, CryptoFileAttributeProvider fileAttributeProvider,
			CryptoFileAttributeViewProvider fileAttributeViewProvider, PathMatcherFactory pathMatcherFactory, CryptoPathFactory cryptoPathFactory, CryptoFileSystemStats stats,
			RootDirectoryInitializer rootDirectoryInitializer, CryptoFileAttributeByNameProvider fileAttributeByNameProvider, DirectoryStreamFactory directoryStreamFactory, FinallyUtil finallyUtil) {
		this.cryptor = cryptor;
		this.provider = provider;
		this.cryptoFileSystems = cryptoFileSystems;
		this.pathToVault = pathToVault;
		this.cryptoPathMapper = cryptoPathMapper;
		this.dirIdProvider = dirIdProvider;
		this.fileAttributeProvider = fileAttributeProvider;
		this.fileAttributeByNameProvider = fileAttributeByNameProvider;
		this.fileAttributeViewProvider = fileAttributeViewProvider;
		this.openCryptoFiles = openCryptoFiles;
		this.fileStore = fileStore;
		this.pathMatcherFactory = pathMatcherFactory;
		this.cryptoPathFactory = cryptoPathFactory;
		this.stats = stats;
		this.directoryStreamFactory = directoryStreamFactory;
		this.rootPath = cryptoPathFactory.rootFor(this);
		this.emptyPath = cryptoPathFactory.emptyFor(this);
		this.finallyUtil = finallyUtil;

		rootDirectoryInitializer.initialize(rootPath);
	}

	@Override
	public Path getPathToVault() {
		return pathToVault;
	}

	@Override
	public CryptoFileSystemStats getStats() {
		return stats;
	}

	/* java.nio.file.FileSystem API */

	@Override
	public FileSystemProvider provider() {
		assertOpen();
		return provider;
	}

	@Override
	public boolean isReadOnly() {
		assertOpen();
		// TODO
		return false;
	}

	@Override
	public String getSeparator() {
		assertOpen();
		return SEPARATOR;
	}

	@Override
	public Iterable<Path> getRootDirectories() {
		assertOpen();
		return Collections.singleton(getRootPath());
	}

	@Override
	public Iterable<FileStore> getFileStores() {
		assertOpen();
		return Collections.singleton(fileStore);
	}

	@SuppressWarnings("unchecked")
	@Override
	public void close() throws IOException {
		// TODO close watch services when implemented
		if (open) {
			open = false;
			finallyUtil.guaranteeInvocationOf( //
					() -> cryptoFileSystems.remove(this), //
					() -> openCryptoFiles.close(), //
					() -> directoryStreamFactory.close(), //
					() -> cryptor.destroy());
		}
	}

	@Override
	public boolean isOpen() {
		return open;
	}

	@Override
	public Set<String> supportedFileAttributeViews() {
		assertOpen();
		return fileStore.supportedFileAttributeViewNames();
	}

	@Override
	public CryptoPath getPath(String first, String... more) {
		assertOpen();
		return cryptoPathFactory.getPath(this, first, more);
	}

	@Override
	public PathMatcher getPathMatcher(String syntaxAndPattern) {
		assertOpen();
		return pathMatcherFactory.pathMatcherFrom(syntaxAndPattern);
	}

	@Override
	public UserPrincipalLookupService getUserPrincipalLookupService() {
		assertOpen();
		throw new UnsupportedOperationException();
	}

	@Override
	public WatchService newWatchService() throws IOException {
		assertOpen();
		throw new UnsupportedOperationException();
	}

	/* methods delegated to by CryptoFileSystemProvider */

	void setAttribute(CryptoPath cleartextPath, String attribute, Object value, LinkOption... options) throws IOException {
		Path ciphertextDirPath = cryptoPathMapper.getCiphertextDirPath(cleartextPath);
		if (Files.notExists(ciphertextDirPath) && cleartextPath.getNameCount() > 0) {
			Path ciphertextFilePath = cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.FILE);
			fileAttributeByNameProvider.setAttribute(ciphertextFilePath, attribute, value);
		} else {
			fileAttributeByNameProvider.setAttribute(ciphertextDirPath, attribute, value);
		}
	}

	Map<String, Object> readAttributes(CryptoPath cleartextPath, String attributes, LinkOption... options) throws IOException {
		Path ciphertextDirPath = cryptoPathMapper.getCiphertextDirPath(cleartextPath);
		if (Files.notExists(ciphertextDirPath) && cleartextPath.getNameCount() > 0) {
			Path ciphertextFilePath = cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.FILE);
			return fileAttributeByNameProvider.readAttributes(ciphertextFilePath, attributes);
		} else {
			return fileAttributeByNameProvider.readAttributes(ciphertextDirPath, attributes);
		}
	}

	<A extends BasicFileAttributes> A readAttributes(CryptoPath cleartextPath, Class<A> type, LinkOption... options) throws IOException {
		Path ciphertextDirPath = cryptoPathMapper.getCiphertextDirPath(cleartextPath);
		if (Files.notExists(ciphertextDirPath) && cleartextPath.getNameCount() > 0) {
			Path ciphertextFilePath = cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.FILE);
			return fileAttributeProvider.readAttributes(ciphertextFilePath, type);
		} else {
			return fileAttributeProvider.readAttributes(ciphertextDirPath, type);
		}
	}

	/**
	 * @param cleartextPath the path to the file
	 * @param type the Class object corresponding to the file attribute view
	 * @param options future use
	 * @return a file attribute view of the specified type, or <code>null</code> if the attribute view type is not available
	 * @see CryptoFileAttributeViewProvider#getAttributeView(Path, Class)
	 */
	<V extends FileAttributeView> V getFileAttributeView(CryptoPath cleartextPath, Class<V> type, LinkOption... options) {
		try {
			Path ciphertextDirPath = cryptoPathMapper.getCiphertextDirPath(cleartextPath);
			if (Files.notExists(ciphertextDirPath) && cleartextPath.getNameCount() > 0) {
				Path ciphertextFilePath = cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.FILE);
				return fileAttributeViewProvider.getAttributeView(ciphertextFilePath, type);
			} else {
				return fileAttributeViewProvider.getAttributeView(ciphertextDirPath, type);
			}
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	void checkAccess(CryptoPath cleartextPath, AccessMode... modes) throws IOException {
		if (fileStore.supportsFileAttributeView(PosixFileAttributeView.class)) {
			Set<PosixFilePermission> permissions = readAttributes(cleartextPath, PosixFileAttributes.class).permissions();
			boolean accessDenied = Arrays.stream(modes).anyMatch(accessMode -> !hasAccess(permissions, accessMode));
			if (accessDenied) {
				throw new AccessDeniedException(cleartextPath.toString());
			}
		} else if (fileStore.supportsFileAttributeView(DosFileAttributeView.class)) {
			DosFileAttributes attrs = readAttributes(cleartextPath, DosFileAttributes.class);
			if (ArrayUtils.contains(modes, AccessMode.WRITE) && attrs.isReadOnly()) {
				throw new AccessDeniedException(cleartextPath.toString(), null, "read only file");
			}
		} else {
			// read attributes to check for file existence / throws IOException if file does not exist
			readAttributes(cleartextPath, BasicFileAttributes.class);
		}
	}

	private boolean hasAccess(Set<PosixFilePermission> permissions, AccessMode accessMode) {
		switch (accessMode) {
		case READ:
			return permissions.contains(PosixFilePermission.OWNER_READ);
		case WRITE:
			return permissions.contains(PosixFilePermission.OWNER_WRITE);
		case EXECUTE:
			return permissions.contains(PosixFilePermission.OWNER_EXECUTE);
		default:
			throw new UnsupportedOperationException("AccessMode " + accessMode + " not supported.");
		}
	}

	boolean isHidden(CryptoPath cleartextPath) throws IOException {
		DosFileAttributeView view = this.getFileAttributeView(cleartextPath, DosFileAttributeView.class);
		if (view != null) {
			return view.readAttributes().isHidden();
		} else {
			return false;
		}
	}

	void createDirectory(CryptoPath cleartextDir, FileAttribute<?>... attrs) throws IOException {
		CryptoPath cleartextParentDir = cleartextDir.getParent();
		if (cleartextParentDir == null) {
			return;
		}
		Path ciphertextParentDir = cryptoPathMapper.getCiphertextDirPath(cleartextParentDir);
		if (!Files.exists(ciphertextParentDir)) {
			throw new NoSuchFileException(cleartextParentDir.toString());
		}
		Path ciphertextFile = cryptoPathMapper.getCiphertextFilePath(cleartextDir, CiphertextFileType.FILE);
		if (Files.exists(ciphertextFile)) {
			throw new FileAlreadyExistsException(cleartextDir.toString());
		}
		Path ciphertextDirFile = cryptoPathMapper.getCiphertextFilePath(cleartextDir, CiphertextFileType.DIRECTORY);
		Directory ciphertextDir = cryptoPathMapper.getCiphertextDir(cleartextDir);
		// atomically check for FileAlreadyExists and create otherwise:
		try (FileChannel channel = FileChannel.open(ciphertextDirFile, EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), attrs)) {
			channel.write(ByteBuffer.wrap(ciphertextDir.dirId.getBytes(UTF_8)));
		}
		// create dir if and only if the dirFile has been created right now (not if it has been created before):
		try {
			Files.createDirectories(ciphertextDir.path);
		} catch (IOException e) {
			// make sure there is no orphan dir file:
			Files.delete(ciphertextDirFile);
			dirIdProvider.delete(ciphertextDirFile);
			throw e;
		}
	}

	DirectoryStream<Path> newDirectoryStream(CryptoPath cleartextDir, Filter<? super Path> filter) throws IOException {
		return directoryStreamFactory.newDirectoryStream(cleartextDir, filter);
	}

	FileChannel newFileChannel(CryptoPath cleartextPath, Set<? extends OpenOption> optionsSet, FileAttribute<?>... attrs) throws IOException {
		EffectiveOpenOptions options = EffectiveOpenOptions.from(optionsSet);
		Path ciphertextPath = cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.FILE);
		return openCryptoFiles.get(ciphertextPath, options).newFileChannel(options);
	}

	void delete(CryptoPath cleartextPath) throws IOException {
		Path ciphertextFile = cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.FILE);
		// try to delete ciphertext file:
		if (!Files.deleteIfExists(ciphertextFile)) {
			// filePath doesn't exist, maybe it's an directory:
			Path ciphertextDir = cryptoPathMapper.getCiphertextDirPath(cleartextPath);
			Path ciphertextDirFile = cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.DIRECTORY);
			try {
				Files.delete(ciphertextDir);
				if (!Files.deleteIfExists(ciphertextDirFile)) {
					// should not happen. Nevertheless this is a valid state, so who no big deal...
					LOG.warn("Successfully deleted dir {}, but didn't find corresponding dir file {}", ciphertextDir, ciphertextDirFile);
				}
				dirIdProvider.delete(ciphertextDirFile);
			} catch (NoSuchFileException e) {
				// translate ciphertext path to cleartext path
				throw new NoSuchFileException(cleartextPath.toString());
			} catch (DirectoryNotEmptyException e) {
				// translate ciphertext path to cleartext path
				throw new DirectoryNotEmptyException(cleartextPath.toString());
			}
		}
	}

	void copy(CryptoPath cleartextSource, CryptoPath cleartextTarget, CopyOption... options) throws IOException {
		if (cleartextSource.equals(cleartextTarget)) {
			return;
		}
		Path ciphertextSourceFile = cryptoPathMapper.getCiphertextFilePath(cleartextSource, CiphertextFileType.FILE);
		Path ciphertextSourceDirFile = cryptoPathMapper.getCiphertextFilePath(cleartextSource, CiphertextFileType.DIRECTORY);
		if (Files.exists(ciphertextSourceFile)) {
			// FILE:
			Path ciphertextTargetFile = cryptoPathMapper.getCiphertextFilePath(cleartextTarget, CiphertextFileType.FILE);
			Files.copy(ciphertextSourceFile, ciphertextTargetFile, options);
		} else if (Files.exists(ciphertextSourceDirFile)) {
			// DIRECTORY (non-recursive as per contract):
			Path ciphertextTargetDirFile = cryptoPathMapper.getCiphertextFilePath(cleartextTarget, CiphertextFileType.DIRECTORY);
			if (!Files.exists(ciphertextTargetDirFile)) {
				// create new:
				createDirectory(cleartextTarget);
			} else if (ArrayUtils.contains(options, StandardCopyOption.REPLACE_EXISTING)) {
				// keep existing (if empty):
				Path ciphertextTargetDir = cryptoPathMapper.getCiphertextDirPath(cleartextTarget);
				try (DirectoryStream<Path> ds = Files.newDirectoryStream(ciphertextTargetDir)) {
					if (ds.iterator().hasNext()) {
						throw new DirectoryNotEmptyException(cleartextTarget.toString());
					}
				}
			} else {
				throw new FileAlreadyExistsException(cleartextTarget.toString());
			}
			if (ArrayUtils.contains(options, StandardCopyOption.COPY_ATTRIBUTES)) {
				Path ciphertextSourceDir = cryptoPathMapper.getCiphertextDirPath(cleartextSource);
				Path ciphertextTargetDir = cryptoPathMapper.getCiphertextDirPath(cleartextTarget);
				copyAttributes(ciphertextSourceDir, ciphertextTargetDir);
			}
		} else {
			throw new NoSuchFileException(cleartextSource.toString());
		}
	}

	private void copyAttributes(Path src, Path dst) throws IOException {
		Set<Class<? extends FileAttributeView>> supportedAttributeViewTypes = fileStore.supportedFileAttributeViewTypes();
		if (supportedAttributeViewTypes.contains(BasicFileAttributeView.class)) {
			BasicFileAttributes srcAttrs = Files.readAttributes(src, BasicFileAttributes.class);
			BasicFileAttributeView dstAttrView = Files.getFileAttributeView(dst, BasicFileAttributeView.class);
			dstAttrView.setTimes(srcAttrs.lastModifiedTime(), srcAttrs.lastAccessTime(), srcAttrs.creationTime());
		}
		if (supportedAttributeViewTypes.contains(FileOwnerAttributeView.class)) {
			FileOwnerAttributeView srcAttrView = Files.getFileAttributeView(src, FileOwnerAttributeView.class);
			FileOwnerAttributeView dstAttrView = Files.getFileAttributeView(dst, FileOwnerAttributeView.class);
			dstAttrView.setOwner(srcAttrView.getOwner());
		}
		if (supportedAttributeViewTypes.contains(PosixFileAttributeView.class)) {
			PosixFileAttributes srcAttrs = Files.readAttributes(src, PosixFileAttributes.class);
			PosixFileAttributeView dstAttrView = Files.getFileAttributeView(dst, PosixFileAttributeView.class);
			dstAttrView.setGroup(srcAttrs.group());
			dstAttrView.setPermissions(srcAttrs.permissions());
		}
		if (supportedAttributeViewTypes.contains(DosFileAttributeView.class)) {
			DosFileAttributes srcAttrs = Files.readAttributes(src, DosFileAttributes.class);
			DosFileAttributeView dstAttrView = Files.getFileAttributeView(dst, DosFileAttributeView.class);
			dstAttrView.setArchive(srcAttrs.isArchive());
			dstAttrView.setHidden(srcAttrs.isHidden());
			dstAttrView.setReadOnly(srcAttrs.isReadOnly());
			dstAttrView.setSystem(srcAttrs.isSystem());
		}
	}

	void move(CryptoPath cleartextSource, CryptoPath cleartextTarget, CopyOption... options) throws IOException {
		if (cleartextSource.equals(cleartextTarget)) {
			return;
		}
		Path ciphertextSourceFile = cryptoPathMapper.getCiphertextFilePath(cleartextSource, CiphertextFileType.FILE);
		Path ciphertextSourceDirFile = cryptoPathMapper.getCiphertextFilePath(cleartextSource, CiphertextFileType.DIRECTORY);
		if (Files.exists(ciphertextSourceFile)) {
			// FILE:
			Path ciphertextTargetFile = cryptoPathMapper.getCiphertextFilePath(cleartextTarget, CiphertextFileType.FILE);
			Files.move(ciphertextSourceFile, ciphertextTargetFile, options);
		} else if (Files.exists(ciphertextSourceDirFile)) {
			// DIRECTORY:
			Path ciphertextTargetDirFile = cryptoPathMapper.getCiphertextFilePath(cleartextTarget, CiphertextFileType.DIRECTORY);
			if (!ArrayUtils.contains(options, StandardCopyOption.REPLACE_EXISTING)) {
				// try to move, don't replace:
				Files.move(ciphertextSourceDirFile, ciphertextTargetDirFile, options);
			} else if (ArrayUtils.contains(options, StandardCopyOption.ATOMIC_MOVE)) {
				// replace atomically (impossible):
				assert ArrayUtils.contains(options, StandardCopyOption.REPLACE_EXISTING);
				throw new AtomicMoveNotSupportedException(cleartextSource.toString(), cleartextTarget.toString(), "Replacing directories during move requires non-atomic status checks.");
			} else {
				// move and replace (if dir is empty):
				assert ArrayUtils.contains(options, StandardCopyOption.REPLACE_EXISTING);
				assert !ArrayUtils.contains(options, StandardCopyOption.ATOMIC_MOVE);
				if (Files.exists(ciphertextTargetDirFile)) {
					Path ciphertextTargetDir = cryptoPathMapper.getCiphertextDirPath(cleartextTarget);
					try (DirectoryStream<Path> ds = Files.newDirectoryStream(ciphertextTargetDir)) {
						if (ds.iterator().hasNext()) {
							throw new DirectoryNotEmptyException(cleartextTarget.toString());
						}
					}
					Files.delete(ciphertextTargetDir);
				}
				Files.move(ciphertextSourceDirFile, ciphertextTargetDirFile, options);
			}
			dirIdProvider.move(ciphertextSourceDirFile, ciphertextTargetDirFile);
		} else {
			throw new NoSuchFileException(cleartextSource.toString());
		}
	}

	CryptoFileStore getFileStore() {
		return fileStore;
	}

	/* internal methods */

	CryptoPath getRootPath() {
		return rootPath;
	}

	CryptoPath getEmptyPath() {
		return emptyPath;
	}

	void assertOpen() {
		if (!open) {
			throw new ClosedFileSystemException();
		}
	}

	@Override
	public String toString() {
		return format("%sCryptoFileSystem(%s)", open ? "" : "closed ", pathToVault);
	}

}
