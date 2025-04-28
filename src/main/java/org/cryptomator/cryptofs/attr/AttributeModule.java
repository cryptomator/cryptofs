package org.cryptomator.cryptofs.attr;

import dagger.Module;
import dagger.Provides;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.fh.OpenCryptoFile;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;
import org.cryptomator.cryptolib.api.Cryptor;

import jakarta.inject.Named;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.Optional;

@Module
abstract class AttributeModule {
	
	@Provides
	@AttributeScoped
	public static Optional<OpenCryptoFile> provideOpenCryptoFile(OpenCryptoFiles openCryptoFiles, Path ciphertextPath) {
		return openCryptoFiles.get(ciphertextPath);
	}

	@Provides
	@Named("cleartext")
	@AttributeScoped
	public static BasicFileAttributes provideAttributes(@Named("ciphertext") BasicFileAttributes ciphertextAttributes, CiphertextFileType ciphertextFileType, Path ciphertextPath, Cryptor cryptor, Optional<OpenCryptoFile> openCryptoFile, CryptoFileSystemProperties fileSystemProperties) {
		if (ciphertextAttributes instanceof PosixFileAttributes attr) {
			return new CryptoPosixFileAttributes(attr, ciphertextFileType, ciphertextPath, cryptor, openCryptoFile, fileSystemProperties);
		} else if (ciphertextAttributes instanceof DosFileAttributes attr) {
			return new CryptoDosFileAttributes(attr, ciphertextFileType, ciphertextPath, cryptor, openCryptoFile, fileSystemProperties);
		} else {
			return new CryptoBasicFileAttributes(ciphertextAttributes, ciphertextFileType, ciphertextPath, cryptor, openCryptoFile);
		}
	}
	
}
