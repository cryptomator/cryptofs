package org.cryptomator.cryptofs;

import java.util.Arrays;
import java.util.Objects;

/**
 * Functions used from commons-lang
 */
final class ArrayUtils {

	public static boolean contains(Object[] array, Object objectToFind) {
		return Arrays.stream(Objects.requireNonNull(array)).anyMatch(Objects.requireNonNull(objectToFind)::equals);
	}

}
