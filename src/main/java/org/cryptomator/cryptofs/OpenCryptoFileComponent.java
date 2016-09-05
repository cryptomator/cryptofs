package org.cryptomator.cryptofs;

import dagger.Subcomponent;

@Subcomponent(modules = {OpenCryptoFileModule.class})
@PerOpenFile
interface OpenCryptoFileComponent {

	OpenCryptoFile openCryptoFile();

}
