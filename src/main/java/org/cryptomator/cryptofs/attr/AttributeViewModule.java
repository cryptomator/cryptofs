package org.cryptomator.cryptofs.attr;

import dagger.Binds;
import dagger.Module;
import dagger.Provides;
import dagger.multibindings.ClassKey;
import dagger.multibindings.IntoMap;

import javax.inject.Provider;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.util.Map;
import java.util.Optional;

@Module
abstract class AttributeViewModule {

	@Binds
	@IntoMap
	@ClassKey(BasicFileAttributeView.class)
	@AttributeViewScoped
	public abstract FileAttributeView provideBasicFileAttributeView(CryptoBasicFileAttributeView view);

	@Binds
	@IntoMap
	@ClassKey(PosixFileAttributeView.class)
	@AttributeViewScoped
	public abstract FileAttributeView providePosixFileAttributeView(CryptoPosixFileAttributeView view);

	@Binds
	@IntoMap
	@ClassKey(DosFileAttributeView.class)
	@AttributeViewScoped
	public abstract FileAttributeView provideDosFileAttributeView(CryptoDosFileAttributeView view);

	@Binds
	@IntoMap
	@ClassKey(FileOwnerAttributeView.class)
	@AttributeViewScoped
	public abstract FileAttributeView provideFileOwnerAttributeView(CryptoFileOwnerAttributeView view);

	@Provides
	@AttributeViewScoped
	public static Optional<FileAttributeView> provideAttributeView(Map<Class<?>, Provider<FileAttributeView>> providers, Class<? extends FileAttributeView> requestedType) {
		Provider<FileAttributeView> provider = providers.get(requestedType);
		if (provider == null) {
			return Optional.empty();
		} else {
			return Optional.of(provider.get());
		}
	}

}
