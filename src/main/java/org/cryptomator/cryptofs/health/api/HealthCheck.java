package org.cryptomator.cryptofs.health.api;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.nio.file.Path;
import java.util.Collection;
import java.util.ServiceLoader;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Stream;

public interface HealthCheck {

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
	 * @param config The parsed and verified vault config
	 * @param masterkey The masterkey
	 * @param cryptor A cryptor initialized for this vault
	 * @return Diagnostic results
	 */
	default Stream<DiagnosticResult> check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) {
		return check(pathToVault, config, masterkey, cryptor, ForkJoinPool.commonPool());
	}

	/**
	 * Checks the vault at the given path.
	 *
	 * @param pathToVault Path to the vault's root directory
	 * @param config The parsed and verified vault config
	 * @param masterkey The masterkey
	 * @param cryptor A cryptor initialized for this vault
	 * @param executor An executor service to run the health check
	 * @return Diagnostic results
	 */
	Stream<DiagnosticResult> check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor, ExecutorService executor);

	/**
	 * Attempts to cancel this health check (if it is running).
	 *
	 * Calling this method does not guarantee that no further results are produced due to async behaviour.
	 */
	void cancel();

	static Collection<HealthCheck> allChecks() {
		return ServiceLoader.load(HealthCheck.class).stream().map(ServiceLoader.Provider::get).toList();
	}

}
