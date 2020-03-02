package org.cryptomator.cryptofs.attr;

import dagger.Binds;
import dagger.Module;
import dagger.Provides;
import dagger.multibindings.ClassKey;
import dagger.multibindings.IntoMap;
import org.cryptomator.cryptofs.fh.OpenCryptoFile;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;

import javax.inject.Provider;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.Map;
import java.util.Optional;

@Module
abstract class AttributeModule {
	
	@Provides
	@AttributeScoped
	public static Optional<OpenCryptoFile> provideOpenCryptoFile(OpenCryptoFiles openCryptoFiles, Path ciphertextPath) {
		return openCryptoFiles.get(ciphertextPath);
	}
	
	@Provides
	@AttributeScoped
	public static PosixFileAttributes providePosixFileAttributes(BasicFileAttributes ciphertextAttributes) {
		if (ciphertextAttributes instanceof PosixFileAttributes) {
			return (PosixFileAttributes) ciphertextAttributes;
		} else {
			throw new IllegalStateException("Attempted to inject instance of type " + ciphertextAttributes.getClass() + " but expected PosixFileAttributes.");
		}
	}

	@Provides
	@AttributeScoped
	public static DosFileAttributes provideDosFileAttributes(BasicFileAttributes ciphertextAttributes) {
		if (ciphertextAttributes instanceof DosFileAttributes) {
			return (DosFileAttributes) ciphertextAttributes;
		} else {
			throw new IllegalStateException("Attempted to inject instance of type " + ciphertextAttributes.getClass() + " but expected DosFileAttributes.");
		}
	}

	@Binds
	@IntoMap
	@ClassKey(BasicFileAttributes.class)
	@AttributeScoped
	public abstract BasicFileAttributes bindCryptoBasicFileAttributes(CryptoBasicFileAttributes view);

	@Binds
	@IntoMap
	@ClassKey(PosixFileAttributes.class)
	@AttributeScoped
	public abstract BasicFileAttributes bindCryptoPosixFileAttributes(CryptoPosixFileAttributes view);

	@Binds
	@IntoMap
	@ClassKey(DosFileAttributes.class)
	@AttributeScoped
	public abstract BasicFileAttributes bindCryptoDosFileAttributes(CryptoDosFileAttributes view);

	@Provides
	@AttributeScoped
	public static Optional<BasicFileAttributes> provideAttributes(Map<Class<?>, Provider<BasicFileAttributes>> providers, Class<? extends BasicFileAttributes> requestedType) {
		Provider<BasicFileAttributes> provider = providers.get(requestedType);
		if (provider == null) {
			return Optional.empty();
		} else {
			return Optional.of(provider.get());
		}
	}
	
}
