package org.cryptomator.cryptofs.health.api;

import org.cryptomator.cryptolib.api.MasterkeyLoader;

import java.nio.file.Path;
import java.util.Collection;

public interface HealthCheck {

	/**
	 * Tests whether this health check can be run on a vault structure with the given version.
	 *
	 * @param vaultVersion The vault's alleged version
	 * @return <code>true</code> if this health check can be run
	 */
	boolean isApplicable(int vaultVersion);

	/**
	 * @return A unique name for this check (that might be used as a translation key)
	 */
	default String identifier() {
		return getClass().getCanonicalName();
	}

	/**
	 * Checks the vault at the given path.
	 *
	 * @param pathToVault Path to the vault's root directory
	 * @param keyLoader   A key loader capable of providing the key associated with this vault
	 * @return Diagnostic results
	 */
	Collection<DiagnosticResult> check(Path pathToVault, MasterkeyLoader keyLoader);

}
