package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.CryptoFileSystemModule.cryptoFileSystemModule;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

import java.nio.file.Path;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class CryptoFileSystemModuleTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void testBuilderSetsValues() {
		CryptoFileSystemProperties cryptoFileSystemProperties = mock(CryptoFileSystemProperties.class);
		Path path = mock(Path.class);

		CryptoFileSystemModule cryptoFileSystemModule = cryptoFileSystemModule() //
				.withCryptoFileSystemProperties(cryptoFileSystemProperties) //
				.withPathToVault(path) //
				.build();

		assertThat(cryptoFileSystemModule.provideCryptoFileSystemProperties(), is(cryptoFileSystemProperties));
		assertThat(cryptoFileSystemModule.providePathToVault(), is(path));
	}

	@Test
	public void testBuildFailsIfPathToVaultIsMissing() {
		CryptoFileSystemProperties cryptoFileSystemProperties = mock(CryptoFileSystemProperties.class);

		thrown.expect(IllegalStateException.class);
		thrown.expectMessage("pathToVault");

		cryptoFileSystemModule() //
				.withCryptoFileSystemProperties(cryptoFileSystemProperties) //
				.build();
	}

	@Test
	public void testBuildFailsIfCryptoFileSystemPropertiesAreMissing() {
		Path path = mock(Path.class);

		thrown.expect(IllegalStateException.class);
		thrown.expectMessage("cryptoFileSystemProperties");

		cryptoFileSystemModule() //
				.withPathToVault(path) //
				.build();
	}

}
