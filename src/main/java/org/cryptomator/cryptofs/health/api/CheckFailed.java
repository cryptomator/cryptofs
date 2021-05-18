package org.cryptomator.cryptofs.health.api;

public class CheckFailed implements DiagnosticResult {

	private final String message;

	public CheckFailed(String message) {
		this.message = message;
	}

	@Override
	public Severity getSeverity() {
		return Severity.CRITICAL;
	}

	@Override
	public String toString() {
		return String.format("Check failed: %s", message);
	}
}
