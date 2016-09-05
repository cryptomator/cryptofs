package org.cryptomator.cryptofs;

import dagger.Component;

@PerProvider
@Component(modules = {CryptoFileSystemProviderModule.class, CryptoFileSystemProviderFactoryModule.class})
interface CryptoFileSystemProviderComponent {

	CryptoFileSystems fileSystems();

	CryptoFileSystemComponent newCryptoFileSystemComponent(CryptoFileSystemModule cryptoFileSystemModule);

}