package org.cryptomator.cryptofs;

import static org.hamcrest.Matchers.is;

import java.nio.file.Path;

import org.hamcrest.FeatureMatcher;
import org.hamcrest.Matcher;

public class CryptoFileSystemModuleMatcher {

	public static Matcher<CryptoFileSystemModule> withPathToVault(Path path) {
		return new FeatureMatcher<CryptoFileSystemModule, Path>(is(path), "path", "path") {
			@Override
			protected Path featureValueOf(CryptoFileSystemModule actual) {
				return actual.providePathToVault();
			}
		};
	}

	public static Matcher<CryptoFileSystemModule> withProperties(CryptoFileSystemProperties properties) {
		return new FeatureMatcher<CryptoFileSystemModule, CryptoFileSystemProperties>(is(properties), "properties", "properties") {
			@Override
			protected CryptoFileSystemProperties featureValueOf(CryptoFileSystemModule actual) {
				return actual.provideCryptoFileSystemProperties();
			}
		};
	}

}
