package org.cryptomator.cryptofs.health.api;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.Collection;
import java.util.ServiceLoader;
import java.util.concurrent.ExecutorService;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public interface HealthCheck {

	/**
	 * @return All known health checks
	 */
	static Collection<HealthCheck> allChecks() {
		return ServiceLoader.load(HealthCheck.class).stream().map(ServiceLoader.Provider::get).toList();
	}

	/**
	 * @return A human readable name for this check
	 */
	default String name() {
		var canonicalName = getClass().getCanonicalName();
		return canonicalName.substring(canonicalName.lastIndexOf('.')+1);
	}

	/**
	 * Checks the vault at the given path.
	 *
	 * @param pathToVault     Path to the vault's root directory
	 * @param config          The parsed and verified vault config
	 * @param masterkey       The masterkey
	 * @param cryptor         A cryptor initialized for this vault
	 * @param resultCollector Callback called for each result.
	 */
	void check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor, Consumer<DiagnosticResult> resultCollector);

	/**
	 * Invokes the health check on a background thread scheduled using the given executor service. The results will be
	 * streamed. If the stream gets {@link Stream#close() closed} before it terminates, an attempt is made to cancel
	 * the health check.
	 * <p>
	 * The check blocks if the stream is not consumed
	 *
	 * @param pathToVault Path to the vault's root directory
	 * @param config      The parsed and verified vault config
	 * @param masterkey   The masterkey
	 * @param cryptor     A cryptor initialized for this vault
	 * @param executor    An executor service to run the health check
	 * @return A lazily filled stream of diagnostic results.
	 */
	default Stream<DiagnosticResult> check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor, ExecutorService executor) {
		var resultSpliterator = new TransferSpliterator<DiagnosticResult>(new PoisonResult());

		var task = executor.submit(() -> {
			try {
				check(pathToVault, config, masterkey, cryptor, resultSpliterator);
			} catch (TransferSpliterator.TransferClosedException e) {
				LoggerFactory.getLogger(HealthCheck.class).debug("{} cancelled.", name());
			} finally {
				resultSpliterator.close();
			}
		});

		return StreamSupport.stream(resultSpliterator, false).onClose(() -> task.cancel(true));
	}

}