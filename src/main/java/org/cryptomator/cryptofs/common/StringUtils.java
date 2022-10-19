package org.cryptomator.cryptofs.common;

/**
 * Functions used from commons-lang
 */
public final class StringUtils {

	/**
	 * Removes the suffix of a string, if the string ends with the suffix.
	 *
	 * @param str input string
	 * @param remove the suffix to match and remove
	 * @return a copy of {@code str} with the suffix removed, otherwise just {@code str}
	 */
	public static String removeEnd(String str, String remove) {
		if (str == null || remove == null) {
			return str;
		}
		if (str.endsWith(remove)) {
			return str.substring(0, str.length() - remove.length());
		} else {
			return str;
		}
	}

}
