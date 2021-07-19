package org.cryptomator.cryptofs.health.type;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptofs.health.api.HealthCheck;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.nio.file.Path;
import java.util.function.Consumer;

public class CipherTextFileTypeCheck implements HealthCheck {

	@Override
	public String name() {
		return "Resource Type Check";
	}

	@Override
	public void check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor, Consumer<DiagnosticResult> resultCollector) {

	}
}
