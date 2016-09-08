package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.Constants.SEPARATOR;

import javax.inject.Inject;

@PerProvider
class GlobToRegexConverter {

	@Inject
	public GlobToRegexConverter() {
	}

	public String convert(String glob) {
		return GlobToRegex.toRegex(glob, SEPARATOR.charAt(0));
	}

}