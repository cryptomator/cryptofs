package org.cryptomator.cryptofs;

import dagger.Subcomponent;

@PerFileSystem
@Subcomponent(modules = {CryptoFileSystemModule.class})
interface CryptoFileSystemComponent {

	CryptoFileSystemImpl cryptoFileSystem();

	OpenCryptoFileComponent newOpenCryptoFileComponent(OpenCryptoFileModule openCryptoFileModule);

}
