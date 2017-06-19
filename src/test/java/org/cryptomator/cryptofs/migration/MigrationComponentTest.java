package org.cryptomator.cryptofs.migration;

import java.security.NoSuchAlgorithmException;

import org.cryptomator.cryptofs.mocks.NullSecureRandom;
import org.cryptomator.cryptolib.common.SecureRandomModule;
import org.junit.Assert;
import org.junit.Test;

public class MigrationComponentTest {

	@Test
	public void testAvailableMigrators() throws NoSuchAlgorithmException {
		SecureRandomModule secRndModule = new SecureRandomModule(new NullSecureRandom());
		TestMigrationComponent comp = DaggerTestMigrationComponent.builder().secureRandomModule(secRndModule).build();
		Assert.assertFalse(comp.availableMigrators().isEmpty());
	}

}
