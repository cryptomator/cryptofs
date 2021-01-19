package org.cryptomator.cryptofs.health.api;

public class DiagnosticResult {

	public enum Severity {
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
	private final String message;

	protected DiagnosticResult(Severity severity, String message) {
		this.severity = severity;
		this.message = message;
	}

	public void fix() {
		// TODO API not yet defined
	}

}
