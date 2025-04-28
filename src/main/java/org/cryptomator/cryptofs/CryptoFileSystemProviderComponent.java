package org.cryptomator.cryptofs;

import dagger.BindsInstance;
import dagger.Component;

import jakarta.inject.Singleton;
import java.security.SecureRandom;

@Singleton
@Component(modules = {CryptoFileSystemProviderModule.class})
interface CryptoFileSystemProviderComponent {

	CryptoFileSystems fileSystems();

	MoveOperation moveOperation();

	CopyOperation copyOperation();

	@Component.Builder
	interface Builder {
		@BindsInstance
		Builder csprng(SecureRandom csprng);

		CryptoFileSystemProviderComponent build();
	}

}