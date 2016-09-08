package org.cryptomator.cryptofs;

import dagger.Subcomponent;

@PerFileSystem
@Subcomponent(modules = {CryptoFileSystemModule.class, CryptoFileSystemFactoryModule.class})
interface CryptoFileSystemComponent {

	CryptoFileSystem cryptoFileSystem();

	OpenCryptoFileComponent newOpenCryptoFileComponent(OpenCryptoFileModule openCryptoFileModule);

}
