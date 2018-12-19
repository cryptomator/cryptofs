package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotLinkException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.util.EnumSet;

import static java.nio.charset.StandardCharsets.UTF_8;

@PerFileSystem
class Symlinks {

	private final CryptoPathMapper cryptoPathMapper;
	private final OpenCryptoFiles openCryptoFiles;
	private final ReadonlyFlag readonlyFlag;

	@Inject
	public Symlinks(CryptoPathMapper cryptoPathMapper, OpenCryptoFiles openCryptoFiles, ReadonlyFlag readonlyFlag) {
		this.cryptoPathMapper = cryptoPathMapper;
		this.openCryptoFiles = openCryptoFiles;
		this.readonlyFlag = readonlyFlag;
	}

	public void createSymbolicLink(CryptoPath cleartextPath, Path target, FileAttribute<?>[] attrs) throws IOException {
		cryptoPathMapper.assertNonExisting(cleartextPath);
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

	public CryptoPath readSymbolicLink(CryptoPath cleartextPath) throws IOException {
		Path ciphertextSymlinkFile = cryptoPathMapper.getCiphertextFilePath(cleartextPath, CiphertextFileType.SYMLINK);
		EffectiveOpenOptions openOptions = EffectiveOpenOptions.from(EnumSet.of(StandardOpenOption.READ), readonlyFlag);
		try (OpenCryptoFile f = openCryptoFiles.getOrCreate(ciphertextSymlinkFile, openOptions);
			 FileChannel ch = f.newFileChannel(openOptions)) {
			if (ch.size() > Constants.MAX_SYMLINK_LENGTH) {
				throw new NotLinkException(cleartextPath.toString(), null, "Unreasonably large file");
			}
			ByteBuffer buf = ByteBuffer.allocate((int) ch.size());
			ch.read(buf);
			buf.flip();
			return cleartextPath.resolveSibling(UTF_8.decode(buf).toString());
		}
	}

}
