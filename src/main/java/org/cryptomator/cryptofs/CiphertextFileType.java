package org.cryptomator.cryptofs;

import java.util.Arrays;
import java.util.function.Predicate;
import java.util.stream.Stream;

/**
 * Filename prefix as defined <a href="https://github.com/cryptomator/cryptofs/issues/38">issue 38</a>.
 */
public enum CiphertextFileType {
	FILE(""), DIRECTORY("0"), SYMLINK("1S");

	private final String prefix;

	CiphertextFileType(String prefix) {
		this.prefix = prefix;
	}

	@Deprecated
	public String getPrefix() {
		return prefix;
	}

	public boolean isTypeOfFile(String filename) {
		return filename.startsWith(prefix);
	}

	public static CiphertextFileType forFileName(String filename) {
		return nonTrivialValues().filter(type -> type.isTypeOfFile(filename)).findAny().orElse(CiphertextFileType.FILE);
	}

	public static Stream<CiphertextFileType> nonTrivialValues() {
		Predicate<CiphertextFileType> isTrivial = FILE::equals;
		return Arrays.stream(values()).filter(isTrivial.negate());
	}
}
