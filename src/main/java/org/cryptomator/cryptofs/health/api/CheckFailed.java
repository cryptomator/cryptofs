package org.cryptomator.cryptofs.health.api;

public class CheckFailed extends DiagnosticResult {

	private final String message;

	public CheckFailed(String message) {
		super(Severity.CRITICAL);
		this.message = message;
	}

	@Override
	public String toString() {
		return String.format("Check failed: %s", message);
	}
}
