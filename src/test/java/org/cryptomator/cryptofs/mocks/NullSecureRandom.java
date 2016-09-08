package org.cryptomator.cryptofs.mocks;

import static java.util.Arrays.fill;

import java.security.SecureRandom;

public class NullSecureRandom extends SecureRandom {

	public static final NullSecureRandom INSTANCE = new NullSecureRandom();

	@Override
	public void nextBytes(byte[] bytes) {
		fill(bytes, (byte) 0x00);
	};

}
