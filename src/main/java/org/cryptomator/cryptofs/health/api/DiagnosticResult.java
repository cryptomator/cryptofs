package org.cryptomator.cryptofs.health.api;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

public interface DiagnosticResult {

	enum Severity {
		/**
		 * No complains
		 */
		GOOD,

		/**
		 * No impact on vault structure, no data lass, but noteworthy.
		 * <p>
		 * If a fix is present, applying it is recommended.
		 */
		INFO,

		/**
		 * Compromises vault structure, but no apparent data loss.
		 * <p>
		 * If a fix is present, applying it is highly advised to prevent data loss.
		 */
		WARN,

		/**
		 * Compromises vault structure, data loss happened.
		 * <p>
		 * Restore from backups is advised.
		 * If not possible and a fix present, applying it is recommended to restore vault structure.
		 */
		CRITICAL;
	}

	Severity getSeverity();

	/**
	 * @return A short, human-readable summary of the result.
	 */
	@Override
	String toString();

	/**
	 * A fix for the result.
	 * <p>
	 * "Fix" does not imply to restore lost data. It only implies, that the issue leading to this result is resolved.
	 *
	 * @param pathToVault path to the root directory of the vault
	 * @param config the vault config
	 * @param masterkey the masterkey of the vault
	 * @param cryptor
	 * @throws IOException
	 * @throws UnsupportedOperationException if no fix is implemented for this result
	 * @deprecated Use {@link #getFix(Path, VaultConfig, Masterkey, Cryptor)} instead
	 */
	@Deprecated
	default void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		throw new UnsupportedOperationException("Fix for result" + this.getClass() + " not implemented");
	}

	default Optional<Fix> getFix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) {
		return Optional.empty();
	}

	/**
	 * Get more specific info about the result like names of affected resources.
	 *
	 * @return A map of strings containing result specific information
	 */
	default Map<String, String> details() {
		return Map.of();
	}

	@FunctionalInterface
	interface Fix {
		void apply() throws IOException;
	}
}
