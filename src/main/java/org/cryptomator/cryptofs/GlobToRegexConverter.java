package org.cryptomator.cryptofs;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import static org.cryptomator.cryptofs.common.Constants.SEPARATOR;

@Singleton
class GlobToRegexConverter {

	@Inject
	public GlobToRegexConverter() {
	}

	public String convert(String glob) {
		return GlobToRegex.toRegex(glob, SEPARATOR.charAt(0));
	}

}