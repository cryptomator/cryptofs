package org.cryptomator.cryptofs.health.api;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.nio.file.Path;

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

	Severity getServerity();

	/**
	 * @return A short, human-readable summary of the result.
	 */
	String description();

	default void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) {
		throw new UnsupportedOperationException("Preliminary API not yet implemented");
	}

}
