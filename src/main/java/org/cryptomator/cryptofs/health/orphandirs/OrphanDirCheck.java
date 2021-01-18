package org.cryptomator.cryptofs.health.orphandirs;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptofs.health.api.HealthCheck;
import org.cryptomator.cryptolib.api.Masterkey;

import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

public class OrphanDirCheck implements HealthCheck {

	@Override
	public Collection<DiagnosticResult> check(Path pathToVault, VaultConfig config, Masterkey masterkey) {
		// read all dir.c9r files and encrypt-then-hash their contents
		// find all d/2/30 dirs
		// report missing d/2/30 dirs as WARN (missing dir -> delete c9r file)
		// report missing dir.c9r files as WARN (orphan dir -> move to L+F)
		return List.of();
	}

}
