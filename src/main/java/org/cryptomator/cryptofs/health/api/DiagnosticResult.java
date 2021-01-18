package org.cryptomator.cryptofs.health.api;

public class DiagnosticResult {

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

	private final Severity severity;

	protected DiagnosticResult(Severity severity) {
		this.severity = severity;
	}

	public void fix() {
		// TODO API not yet defined
	}

}
