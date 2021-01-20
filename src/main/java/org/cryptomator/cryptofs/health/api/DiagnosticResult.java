package org.cryptomator.cryptofs.health.api;

public abstract class DiagnosticResult {

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

	protected DiagnosticResult(Severity severity) {
		this.severity = severity;
	}

	/**
	 * @return A short, human-readable summary of the result.
	 */
	@Override
	public String toString() {
		return getClass().getName() + ": " + severity.name();
	}

	public void fix() {
		// TODO API not yet defined
	}

}
