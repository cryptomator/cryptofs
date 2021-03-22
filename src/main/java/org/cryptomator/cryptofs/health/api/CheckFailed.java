package org.cryptomator.cryptofs.health.api;

public class CheckFailed implements DiagnosticResult {

	private final String message;

	public CheckFailed(String message) {
		this.message = message;
	}

	@Override
	public Severity getServerity() {
		return Severity.CRITICAL;
	}

	@Override
	public String description() {
		return String.format("Check failed: %s", message);
	}
}
