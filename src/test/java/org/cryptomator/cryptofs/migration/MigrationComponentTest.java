package org.cryptomator.cryptofs.migration;

import java.security.NoSuchAlgorithmException;

import org.cryptomator.cryptofs.mocks.NullSecureRandom;
import org.cryptomator.cryptolib.Cryptors;
import org.junit.Assert;
import org.junit.Test;

public class MigrationComponentTest {

	@Test
	public void testAvailableMigrators() throws NoSuchAlgorithmException {
		MigrationModule migrationModule = new MigrationModule(Cryptors.version1(new NullSecureRandom()));
		TestMigrationComponent comp = DaggerTestMigrationComponent.builder().migrationModule(migrationModule).build();
		Assert.assertFalse(comp.availableMigrators().isEmpty());
	}

}
