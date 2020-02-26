package org.cryptomator.cryptofs;

import dagger.Module;
import dagger.Provides;
import org.cryptomator.cryptofs.common.FileSystemCapabilityChecker;

import javax.inject.Singleton;

@Module(subcomponents = {CryptoFileSystemComponent.class})
public class CryptoFileSystemProviderModule {
	
	@Provides
	@Singleton
	public FileSystemCapabilityChecker provideFileSystemCapabilityChecker() {
		return new FileSystemCapabilityChecker();
	}
	
}
