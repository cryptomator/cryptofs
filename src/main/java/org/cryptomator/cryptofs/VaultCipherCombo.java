package org.cryptomator.cryptofs;

import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.CryptorProvider;

import java.security.SecureRandom;
import java.util.function.Function;

/**
 * A combination of different ciphers and/or cipher modes in a Cryptomator vault.
 */
public enum VaultCipherCombo {
	/**
	 * AES-SIV for file name encryption
	 * AES-CTR + HMAC for content encryption
	 */
	SIV_CTRMAC(Cryptors::version1);

// TODO enable eventually (issue 94):
//	/**
//	 * AES-SIV for file name encryption
//	 * AES-GCM for content encryption
//	 */
//	SIV_GCM(Cryptors::version2);

	private final Function<SecureRandom, CryptorProvider> cryptorProvider;

	VaultCipherCombo(Function<SecureRandom, CryptorProvider> cryptorProvider) {
		this.cryptorProvider = cryptorProvider;
	}

	public CryptorProvider getCryptorProvider(SecureRandom csprng) {
		return cryptorProvider.apply(csprng);
	}
}
