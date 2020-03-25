package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.file.FileSystemLoopException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotLinkException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;

@CryptoFileSystemScoped
public class Symlinks {

	private final CryptoPathMapper cryptoPathMapper;
	private final LongFileNameProvider longFileNameProvider;
	private final OpenCryptoFiles openCryptoFiles;
	private final ReadonlyFlag readonlyFlag;

	@Inject
	Symlinks(CryptoPathMapper cryptoPathMapper, LongFileNameProvider longFileNameProvider, OpenCryptoFiles openCryptoFiles, ReadonlyFlag readonlyFlag) {
		this.cryptoPathMapper = cryptoPathMapper;
		this.longFileNameProvider = longFileNameProvider;
		this.openCryptoFiles = openCryptoFiles;
		this.readonlyFlag = readonlyFlag;
	}

	public void createSymbolicLink(CryptoPath cleartextPath, Path target, FileAttribute<?>... attrs) throws IOException {
		cryptoPathMapper.assertNonExisting(cleartextPath);
		if (target.toString().length() > Constants.MAX_SYMLINK_LENGTH) {
			throw new IOException("path length limit exceeded.");
		}
		CiphertextFilePath ciphertextFilePath = cryptoPathMapper.getCiphertextFilePath(cleartextPath);
		EffectiveOpenOptions openOptions = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW), readonlyFlag);
		ByteBuffer content = UTF_8.encode(target.toString());
		Files.createDirectory(ciphertextFilePath.getRawPath());
		openCryptoFiles.writeCiphertextFile(ciphertextFilePath.getSymlinkFilePath(), openOptions, content);
		ciphertextFilePath.persistLongFileName();
	}

	public CryptoPath readSymbolicLink(CryptoPath cleartextPath) throws IOException {
		Path ciphertextSymlinkFile = cryptoPathMapper.getCiphertextFilePath(cleartextPath).getSymlinkFilePath();
		EffectiveOpenOptions openOptions = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.READ), readonlyFlag);
		assertIsSymlink(cleartextPath, ciphertextSymlinkFile);
		try {
			ByteBuffer content = openCryptoFiles.readCiphertextFile(ciphertextSymlinkFile, openOptions, Constants.MAX_SYMLINK_LENGTH);
			return cleartextPath.getFileSystem().getPath(UTF_8.decode(content).toString());
		} catch (BufferUnderflowException e) {
			throw new NotLinkException(cleartextPath.toString(), null, "Unreasonably large symlink file");
		}
	}

	/**
	 * @param cleartextPath
	 * @param ciphertextSymlinkFile
	 * @throws NoSuchFileException If the dir containing {@value Constants#SYMLINK_FILE_NAME} does not exist.
	 * @throws NotLinkException If the resource represented by <code>cleartextPath</code> exists but {@value Constants#SYMLINK_FILE_NAME} does not.
	 * @throws IOException In case of any other I/O error
	 */
	private void assertIsSymlink(CryptoPath cleartextPath, Path ciphertextSymlinkFile) throws IOException {
		Path parentDir = ciphertextSymlinkFile.getParent();
		BasicFileAttributes parentAttr = Files.readAttributes(parentDir, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
		if (parentAttr.isDirectory()) {
			try {
				BasicFileAttributes fileAttr = Files.readAttributes(ciphertextSymlinkFile, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
				if (!fileAttr.isRegularFile()) {
					throw new NotLinkException(cleartextPath.toString(), null, "File exists but is not a symlink.");
				}
			} catch (NoSuchFileException e) {
				throw new NotLinkException(cleartextPath.toString(), null, "File exists but is not a symlink.");
			}
		} else {
			throw new NotLinkException(cleartextPath.toString(), null, "File exists but is not a symlink.");
		}
	}

	/**
	 * Gets the target of a symlink. Recursive, if the target is a symlink itself.
	 * @param cleartextPath A cleartext path. Might be a symlink, otherwise this method is no-op.
	 * @return The resolved cleartext path. Might be the same as <code>cleartextPath</code> if it wasn't a symlink in the first place.
	 * @throws IOException
	 */
	public CryptoPath resolveRecursively(CryptoPath cleartextPath) throws IOException {
		return resolveRecursively(new HashSet<>(), cleartextPath);
	}

	private CryptoPath resolveRecursively(Set<CryptoPath> visitedLinks, CryptoPath cleartextPath) throws IOException {
		if (visitedLinks.contains(cleartextPath)) {
			throw new FileSystemLoopException(cleartextPath.toString());
		}
		CiphertextFileType ciphertextFileType;
		try {
			ciphertextFileType = cryptoPathMapper.getCiphertextFileType(cleartextPath);
		} catch (NoSuchFileException e) {
			// if it doesn't exist, it can't be a symlink. therefore cleartextPath is fully resolved.
			return cleartextPath;
		}
		if (ciphertextFileType == CiphertextFileType.SYMLINK) {
			CryptoPath resolvedPath = readSymbolicLink(cleartextPath);
			visitedLinks.add(cleartextPath);
			return resolveRecursively(visitedLinks, resolvedPath);
		} else {
			return cleartextPath;
		}
	}

}
