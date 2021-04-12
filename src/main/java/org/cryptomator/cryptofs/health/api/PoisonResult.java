package org.cryptomator.cryptofs.health.api;

record PoisonResult() implements DiagnosticResult {
	@Override
	public Severity getServerity() {
		return null;
	}
}