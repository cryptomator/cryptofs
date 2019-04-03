package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.file.FileSystemLoopException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotLinkException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;

@CryptoFileSystemScoped
public class Symlinks {

	private final CryptoPathMapper cryptoPathMapper;
	private final OpenCryptoFiles openCryptoFiles;
	private final ReadonlyFlag readonlyFlag;

	@Inject
	Symlinks(CryptoPathMapper cryptoPathMapper, OpenCryptoFiles openCryptoFiles, ReadonlyFlag readonlyFlag) {
		this.cryptoPathMapper = cryptoPathMapper;
		this.openCryptoFiles = openCryptoFiles;
		this.readonlyFlag = readonlyFlag;
	}

	public void createSymbolicLink(CryptoPath cleartextPath, Path target, FileAttribute<?>... attrs) throws IOException {
		cryptoPathMapper.assertNonExisting(cleartextPath);
		if (target.toString().length() > Constants.MAX_SYMLINK_LENGTH) {
			throw new IOException("path length limit exceeded.");
		}
		Path ciphertextSymlinkFile = cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.SYMLINK);
		EffectiveOpenOptions openOptions = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW), readonlyFlag);
		ByteBuffer content = UTF_8.encode(target.toString());
		openCryptoFiles.writeCiphertextFile(ciphertextSymlinkFile, openOptions, content);
	}

	public CryptoPath readSymbolicLink(CryptoPath cleartextPath) throws IOException {
		Path ciphertextSymlinkFile = cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.SYMLINK);
		EffectiveOpenOptions openOptions = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.READ), readonlyFlag);
		try {
			ByteBuffer content = openCryptoFiles.readCiphertextFile(ciphertextSymlinkFile, openOptions, Constants.MAX_SYMLINK_LENGTH);
			return cleartextPath.getFileSystem().getPath(UTF_8.decode(content).toString());
		} catch (BufferUnderflowException e) {
			throw new NotLinkException(cleartextPath.toString(), null, "Unreasonably large symlink file");
		}
	}

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
