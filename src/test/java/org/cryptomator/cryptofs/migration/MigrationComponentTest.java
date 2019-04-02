package org.cryptomator.cryptofs.migration;

import org.cryptomator.cryptofs.mocks.NullSecureRandom;
import org.cryptomator.cryptolib.Cryptors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

public class MigrationComponentTest {

	@Test
	public void testAvailableMigrators() throws NoSuchAlgorithmException {
		MigrationModule migrationModule = new MigrationModule(Cryptors.version1(NullSecureRandom.INSTANCE));
		TestMigrationComponent comp = DaggerTestMigrationComponent.builder().migrationModule(migrationModule).build();
		Assertions.assertFalse(comp.availableMigrators().isEmpty());
	}

}
