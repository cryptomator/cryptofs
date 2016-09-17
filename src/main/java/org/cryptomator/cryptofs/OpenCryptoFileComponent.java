package org.cryptomator.cryptofs;

import dagger.Subcomponent;

@Subcomponent(modules = {OpenCryptoFileModule.class, OpenCryptoFileFactoryModule.class})
@PerOpenFile
interface OpenCryptoFileComponent {

	OpenCryptoFile openCryptoFile();

}
