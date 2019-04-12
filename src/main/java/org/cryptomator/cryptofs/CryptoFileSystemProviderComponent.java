package org.cryptomator.cryptofs;

import dagger.BindsInstance;
import dagger.Component;
import org.cryptomator.cryptolib.api.CryptorProvider;

import javax.inject.Singleton;

@Singleton
@Component
interface CryptoFileSystemProviderComponent {

	CryptoFileSystems fileSystems();

	MoveOperation moveOperation();

	CopyOperation copyOperation();

	CryptoFileSystemComponent.Builder newCryptoFileSystemComponent();

	@Component.Builder
	interface Builder {
		@BindsInstance
		Builder cryptorProvider(CryptorProvider cryptorProvider);

		CryptoFileSystemProviderComponent build();
	}

}