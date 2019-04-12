package org.cryptomator.cryptofs;

import javax.inject.Inject;
import javax.inject.Singleton;

import static org.cryptomator.cryptofs.Constants.SEPARATOR;

@Singleton
class GlobToRegexConverter {

	@Inject
	public GlobToRegexConverter() {
	}

	public String convert(String glob) {
		return GlobToRegex.toRegex(glob, SEPARATOR.charAt(0));
	}

}