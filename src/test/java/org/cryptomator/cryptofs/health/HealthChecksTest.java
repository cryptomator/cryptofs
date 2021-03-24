package org.cryptomator.cryptofs.health;

import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;
import org.cryptomator.cryptolib.common.MasterkeyFileAccess;
import org.cryptomator.cryptolib.common.MasterkeyFileLoaderContext;

import java.io.Console;
import java.io.IOException;
import java.nio.CharBuffer;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

class HealthChecksTest {

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		try (Scanner scanner = new Scanner(System.in)) {
			System.out.println("Enter path to vault:");
			Path p = Paths.get(scanner.nextLine());

			var masterkeyFileAccess = new MasterkeyFileAccess(new byte[0], SecureRandom.getInstanceStrong());
			MasterkeyLoader loader = masterkeyFileAccess.keyLoader(p, new MasterkeyFileLoaderContext() {
				@Override
				public Path getCorrectMasterkeyFilePath(String s) throws MasterkeyLoadingFailedException {
					return null;
				}

				@Override
				public CharSequence getPassphrase(Path path) throws MasterkeyLoadingFailedException {
					Console console = System.console();
					if (console == null) {
						System.out.println("Enter password for " + path + ":");
						System.out.println("WARNING: PW is not obfuscated");
						return scanner.nextLine();
					} else {
						var pw = console.readPassword("Enter password for %s:", path);
						return CharBuffer.wrap(pw);
					}
				}
			});

			var results = HealthChecks.run(p, "vault.cryptomator", loader, HealthChecks.ALL_CHECKS);
			results.forEach(System.out::println);
		}
	}

}