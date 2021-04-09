package org.cryptomator.cryptofs.health.api;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.common.MasterkeyFileAccess;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.concurrent.Executors;

class HealthCheckIntegrationTest {

	@Test
	public void testGetAll() {
		var result = HealthCheck.allChecks();

		Assertions.assertFalse(result.isEmpty());
	}

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		try (Scanner scanner = new Scanner(System.in)) {
			System.out.println("Enter path to vault:");
			Path p = Paths.get(scanner.nextLine());

			var masterkeyFileAccess = new MasterkeyFileAccess(new byte[0], SecureRandom.getInstanceStrong());
			var masterkeyFile = p.resolve("masterkey.cryptomator");
			var vaultConfigFile = p.resolve("vault.cryptomator");
			var unverifiedCfg = VaultConfig.decode(Files.readString(vaultConfigFile));

			System.out.println("Enter password [WARNING: not obfuscated]");
			String pw = scanner.nextLine();

			try (var masterkey = masterkeyFileAccess.load(masterkeyFile, pw)) {
				var verifiedCfg = unverifiedCfg.verify(masterkey.getEncoded(), unverifiedCfg.allegedVaultVersion());
				var cryptor = verifiedCfg.getCipherCombo().getCryptorProvider(SecureRandom.getInstanceStrong()).withKey(masterkey);
				var executor = Executors.newSingleThreadExecutor();
				HealthCheck.allChecks().forEach(check -> {
					System.out.println("Running " + check.identifier());
					var results = check.check(p, verifiedCfg, masterkey, cryptor, executor);
					results.forEach(System.out::println);
				});
				executor.shutdown();
			}
		}
	}

}