package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import org.cryptomator.cryptolib.Cryptor;

class CryptoPathMapper {

	private static final String ROOT_DIR_ID = "";
	private static final String DIRECTORY_PREFIX = "0";

	private final Cryptor cryptor;
	private final Path dataRoot;
	private final DirectoryIdProvider dirIdProvider;

	public CryptoPathMapper(Cryptor cryptor, Path dataRoot, DirectoryIdProvider dirIdProvider) {
		this.cryptor = cryptor;
		this.dataRoot = dataRoot;
		this.dirIdProvider = dirIdProvider;
	}

	public Path getCiphertextFilePath(Path cleartextPath) throws IOException {
		if (cleartextPath.getNameCount() == 0) {
			throw new IllegalArgumentException("Invalid file path " + cleartextPath);
		}
		Directory dir = getCiphertextDir(cleartextPath.getParent());
		String cleartextName = cleartextPath.getFileName().toString();
		String ciphertextName = cryptor.fileNameCryptor().encryptFilename(cleartextName, dir.dirId.getBytes(StandardCharsets.UTF_8));
		return dir.path.resolve(ciphertextName);
	}

	public Path getCiphertextDirPath(Path cleartextPath) throws IOException {
		return getCiphertextDir(cleartextPath).path;
	}

	public Directory getCiphertextDir(Path cleartextPath) throws IOException {
		String dirId = ROOT_DIR_ID;
		Path dirPath = resolveDirectory(dirId);
		for (int i = 0; i < cleartextPath.getNameCount(); i++) {
			String cleartextName = cleartextPath.getName(i).toString();
			String ciphertextName = DIRECTORY_PREFIX + cryptor.fileNameCryptor().encryptFilename(cleartextName, dirId.getBytes(StandardCharsets.UTF_8));
			Path dirFilePath = dirPath.resolve(ciphertextName);
			dirId = dirIdProvider.load(dirFilePath);
			dirPath = resolveDirectory(dirId);
		}
		return new Directory(dirId, dirPath);
	}

	private Path resolveDirectory(String dirId) {
		String dirHash = cryptor.fileNameCryptor().hashDirectoryId(dirId);
		return dataRoot.resolve(dirHash.substring(0, 2)).resolve(dirHash.substring(2));
	}

	public static class Directory {
		public final String dirId;
		public final Path path;

		public Directory(String dirId, Path path) {
			this.dirId = dirId;
			this.path = path;
		}
	}

}
