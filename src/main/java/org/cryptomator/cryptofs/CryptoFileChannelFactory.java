package org.cryptomator.cryptofs;

import java.io.IOException;

import javax.inject.Inject;

@PerOpenFile
class CryptoFileChannelFactory {

	@Inject
	public CryptoFileChannelFactory() {
	}

	public CryptoFileChannel create(OpenCryptoFile openCryptoFile, EffectiveOpenOptions options) throws IOException {
		return new CryptoFileChannel(openCryptoFile, options);
	}

}