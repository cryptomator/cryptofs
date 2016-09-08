package org.cryptomator.cryptofs;

import java.security.SecureRandom;
import java.util.Arrays;

import org.cryptomator.cryptolib.common.SecureRandomModule;

class TestSecureRandomModule extends SecureRandomModule {

	private static final SecureRandom NULL_RANDOM = new SecureRandom() {
		@Override
		public synchronized void nextBytes(byte[] bytes) {
			Arrays.fill(bytes, (byte) 0x00);
		};
	};

	public TestSecureRandomModule() {
		super(null);
	}

	@Override
	public SecureRandom provideFastSecureRandom(SecureRandom ignored) {
		return NULL_RANDOM;
	}

	@Override
	public SecureRandom provideNativeSecureRandom() {
		return NULL_RANDOM;
	}

}
