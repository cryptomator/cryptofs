package org.cryptomator.cryptofs;

import com.google.common.io.BaseEncoding;

import java.nio.file.Path;

public class CiphertextPathValidations {


	private CiphertextPathValidations() {}

	public static boolean isCiphertextContentDir(Path p) {
		var twoCharDir = p.getParent();
		if (twoCharDir == null) {
			return false;
		}
		var testString = twoCharDir.getFileName().toString() + p.getFileName().toString();
		return testString.length() == 32 && BaseEncoding.base32().canDecode(testString);
	}

}
