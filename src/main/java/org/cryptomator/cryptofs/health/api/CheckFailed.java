package org.cryptomator.cryptofs.health.api;

public class CheckFailed extends DiagnosticResult {

	public CheckFailed(String message) {
		super(Severity.CRITICAL, message);
	}
}
