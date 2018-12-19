/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextDirectory;
import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
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
import java.nio.file.NotLinkException;
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

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cryptomator.cryptofs.Constants.SEPARATOR;

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
	private final CiphertextDirectoryDeleter ciphertextDirDeleter;
	private final ReadonlyFlag readonlyFlag;

	private volatile boolean open = true;

	@Inject
	public CryptoFileSystemImpl(@PathToVault Path pathToVault, Cryptor cryptor, CryptoFileSystemProvider provider, CryptoFileSystems cryptoFileSystems, CryptoFileStore fileStore,
								OpenCryptoFiles openCryptoFiles, CryptoPathMapper cryptoPathMapper, DirectoryIdProvider dirIdProvider, CryptoFileAttributeProvider fileAttributeProvider,
								CryptoFileAttributeViewProvider fileAttributeViewProvider, PathMatcherFactory pathMatcherFactory, CryptoPathFactory cryptoPathFactory, CryptoFileSystemStats stats,
								RootDirectoryInitializer rootDirectoryInitializer, CryptoFileAttributeByNameProvider fileAttributeByNameProvider, DirectoryStreamFactory directoryStreamFactory, FinallyUtil finallyUtil,
								CiphertextDirectoryDeleter ciphertextDirDeleter, ReadonlyFlag readonlyFlag) {
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
		this.ciphertextDirDeleter = ciphertextDirDeleter;
		this.readonlyFlag = readonlyFlag;
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
		return readonlyFlag.isSet();
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
		readonlyFlag.assertWritable();
		fileAttributeByNameProvider.setAttribute(cleartextPath, attribute, value);
	}

	Map<String, Object> readAttributes(CryptoPath cleartextPath, String attributes, LinkOption... options) throws IOException {
		return fileAttributeByNameProvider.readAttributes(cleartextPath, attributes);
	}

	<A extends BasicFileAttributes> A readAttributes(CryptoPath cleartextPath, Class<A> type, LinkOption... options) throws IOException {
		return fileAttributeProvider.readAttributes(cleartextPath, type);
	}

	/**
	 * @param cleartextPath the path to the file
	 * @param type          the Class object corresponding to the file attribute view
	 * @param options       future use
	 * @return a file attribute view of the specified type, or <code>null</code> if the attribute view type is not available
	 * @see CryptoFileAttributeViewProvider#getAttributeView(Path, Class)
	 */
	<V extends FileAttributeView> V getFileAttributeView(CryptoPath cleartextPath, Class<V> type, LinkOption... options) {
		return fileAttributeViewProvider.getAttributeView(cleartextPath, type);
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

	/**
	 * Verifies that no node exists for the given path. Otherwise a {@link FileAlreadyExistsException} will be thrown.
	 *
	 * @param cleartextPath A path
	 * @throws FileAlreadyExistsException If the node exists
	 * @throws IOException                If any I/O error occurs while attempting to resolve the ciphertext path
	 */
	private void assertNonExisting(CryptoPath cleartextPath) throws FileAlreadyExistsException, IOException {
		try {
			CiphertextFileType typeIfExistingFile = cryptoPathMapper.getCiphertextFileType(cleartextPath);
			throw new FileAlreadyExistsException(cleartextPath.toString(), null, "For this path there is already a " + typeIfExistingFile);
		} catch (NoSuchFileException e) {
			// good!
		}
	}

	void createDirectory(CryptoPath cleartextDir, FileAttribute<?>... attrs) throws IOException {
		readonlyFlag.assertWritable();
		CryptoPath cleartextParentDir = cleartextDir.getParent();
		if (cleartextParentDir == null) {
			return;
		}
		Path ciphertextParentDir = cryptoPathMapper.getCiphertextDirPath(cleartextParentDir);
		if (!Files.exists(ciphertextParentDir)) {
			throw new NoSuchFileException(cleartextParentDir.toString());
		}
		assertNonExisting(cleartextDir);
		Path ciphertextDirFile = cryptoPathMapper.getCiphertextFilePath(cleartextDir, CiphertextFileType.DIRECTORY);
		CiphertextDirectory ciphertextDir = cryptoPathMapper.getCiphertextDir(cleartextDir);
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
		EffectiveOpenOptions options = EffectiveOpenOptions.from(optionsSet, readonlyFlag);
		Path ciphertextPath = cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.FILE);
		if (options.createNew() && openCryptoFiles.get(ciphertextPath).isPresent()) {
			throw new FileAlreadyExistsException(cleartextPath.toString());
		} else {
			// might also throw FileAlreadyExists:
			return openCryptoFiles.getOrCreate(ciphertextPath, options).newFileChannel(options);
		}
	}

	void delete(CryptoPath cleartextPath) throws IOException {
		readonlyFlag.assertWritable();
		CiphertextFileType ciphertextFileType = cryptoPathMapper.getCiphertextFileType(cleartextPath);
		switch (ciphertextFileType) {
			case DIRECTORY:
				deleteDirectory(cleartextPath);
				return;
			default:
				Path ciphertextFilePath = cryptoPathMapper.getCiphertextFilePath(cleartextPath, ciphertextFileType);
				Files.deleteIfExists(ciphertextFilePath);
				return;
		}
	}

	private void deleteDirectory(CryptoPath cleartextPath) throws IOException {
		Path ciphertextDir = cryptoPathMapper.getCiphertextDirPath(cleartextPath);
		Path ciphertextDirFile = cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.DIRECTORY);
		try {
			ciphertextDirDeleter.deleteCiphertextDirIncludingNonCiphertextFiles(ciphertextDir, cleartextPath);
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

	void copy(CryptoPath cleartextSource, CryptoPath cleartextTarget, CopyOption... options) throws IOException {
		readonlyFlag.assertWritable();
		if (cleartextSource.equals(cleartextTarget)) {
			return;
		}
		CiphertextFileType ciphertextFileType = cryptoPathMapper.getCiphertextFileType(cleartextSource);
		if (!ArrayUtils.contains(options, StandardCopyOption.REPLACE_EXISTING)) {
			assertNonExisting(cleartextTarget);
		}
		switch (ciphertextFileType) {
			case DIRECTORY:
				copyDirectory(cleartextSource, cleartextTarget, options);
				return;
			default:
				Path ciphertextSourceFile = cryptoPathMapper.getCiphertextFilePath(cleartextSource, ciphertextFileType);
				Path ciphertextTargetFile = cryptoPathMapper.getCiphertextFilePath(cleartextTarget, ciphertextFileType);
				Files.copy(ciphertextSourceFile, ciphertextTargetFile, options);
				return;
		}
	}

	private void copyDirectory(CryptoPath cleartextSource, CryptoPath cleartextTarget, CopyOption[] options) throws IOException {
		// DIRECTORY (non-recursive as per contract):
		Path ciphertextTargetDirFile = cryptoPathMapper.getCiphertextFilePath(cleartextTarget, CiphertextFileType.DIRECTORY);
		if (Files.notExists(ciphertextTargetDirFile)) {
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
			throw new FileAlreadyExistsException(cleartextTarget.toString(), null, "Ciphertext file already exists: " + ciphertextTargetDirFile);
		}
		if (ArrayUtils.contains(options, StandardCopyOption.COPY_ATTRIBUTES)) {
			Path ciphertextSourceDir = cryptoPathMapper.getCiphertextDirPath(cleartextSource);
			Path ciphertextTargetDir = cryptoPathMapper.getCiphertextDirPath(cleartextTarget);
			copyAttributes(ciphertextSourceDir, ciphertextTargetDir);
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
		readonlyFlag.assertWritable();
		if (cleartextSource.equals(cleartextTarget)) {
			return;
		}
		CiphertextFileType ciphertextFileType = cryptoPathMapper.getCiphertextFileType(cleartextSource);
		if (!ArrayUtils.contains(options, StandardCopyOption.REPLACE_EXISTING)) {
			assertNonExisting(cleartextTarget);
		}
		switch (ciphertextFileType) {
			case FILE:
				moveFile(cleartextSource, cleartextTarget, options);
				return;
			case DIRECTORY:
				moveDirectory(cleartextSource, cleartextTarget, options);
				return;
			default:
				throw new UnsupportedOperationException("Unhandled node type " + ciphertextFileType);
		}
	}

	private void moveFile(CryptoPath cleartextSource, CryptoPath cleartextTarget, CopyOption[] options) throws IOException {
		// FILE:
		// While moving a file, it is possible to keep the any channels open. In order to make this work
		// we need to re-map the OpenCryptoFile entry.
		Path ciphertextSourceFile = cryptoPathMapper.getCiphertextFilePath(cleartextSource, CiphertextFileType.FILE);
		Path ciphertextTargetFile = cryptoPathMapper.getCiphertextFilePath(cleartextTarget, CiphertextFileType.FILE);
		try (OpenCryptoFiles.TwoPhaseMove twoPhaseMove = openCryptoFiles.prepareMove(ciphertextSourceFile, ciphertextTargetFile)) {
			Files.move(ciphertextSourceFile, ciphertextTargetFile, options);
			twoPhaseMove.commit();
		}
	}

	private void moveDirectory(CryptoPath cleartextSource, CryptoPath cleartextTarget, CopyOption[] options) throws IOException {
		// DIRECTORY:
		// Since we only rename the directory file, all ciphertext paths of subresources stay the same.
		// Hence there is no need to re-map OpenCryptoFile entries.
		Path ciphertextSourceDirFile = cryptoPathMapper.getCiphertextFilePath(cleartextSource, CiphertextFileType.DIRECTORY);
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

	public void createSymbolicLink(CryptoPath cleartextPath, Path target, FileAttribute<?>[] attrs) throws IOException {
		assertNonExisting(cleartextPath);
		if (target.toString().length() > Constants.MAX_SYMLINK_LENGTH) {
			throw new IOException("path length limit exceeded.");
		}
		Path ciphertextSymlinkFile = cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.SYMLINK);
		EffectiveOpenOptions openOptions = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW), readonlyFlag);
		try (OpenCryptoFile f = openCryptoFiles.getOrCreate(ciphertextSymlinkFile, openOptions);
			 FileChannel ch = f.newFileChannel(openOptions)) {
			ch.write(ByteBuffer.wrap(target.toString().getBytes(UTF_8)));
		}
	}

	public Path readSymbolicLink(CryptoPath cleartextPath) throws IOException {
		Path ciphertextSymlinkFile = cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.SYMLINK);
		EffectiveOpenOptions openOptions = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.READ), readonlyFlag);
		try (OpenCryptoFile f = openCryptoFiles.getOrCreate(ciphertextSymlinkFile, openOptions);
			 FileChannel ch = f.newFileChannel(openOptions)) {
			if (ch.size() > Constants.MAX_SYMLINK_LENGTH) {
				throw new NotLinkException(cleartextPath.toString(), null, "Unreasonably large file");
			}
			ByteBuffer buf = ByteBuffer.allocate((int) f.size());
			f.read(buf, 0);
			buf.flip();
			return cleartextPath.resolveSibling(UTF_8.decode(buf).toString());
		}
	}
}
