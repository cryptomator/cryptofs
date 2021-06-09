package org.cryptomator.cryptofs.health.api;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.nio.file.Path;
import java.util.Map;

public interface DiagnosticResult {

	enum Severity {
		/**
		 * No complains
		 */
		GOOD,

		/**
		 * Unexpected, but nothing to worry about. May be worth logging
		 */
		INFO,

		/**
		 * Compromises vault structure, can and should be fixed.
		 */
		WARN,

		/**
		 * Irreversible damage, no automated way of fixing this issue.
		 */
		CRITICAL;
	}

	Severity getSeverity();

	/**
	 * @return A short, human-readable summary of the result.
	 */
	@Override
	String toString();

	default void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) {
		throw new UnsupportedOperationException("Preliminary API not yet implemented");
	}

	/**
	 * Get more specific info about the result like names of affected resources.
	 *
	 * @return A map of strings containing result specific information
	 */
	default Map<String, String> details() {
		return Map.of();
	}
}
