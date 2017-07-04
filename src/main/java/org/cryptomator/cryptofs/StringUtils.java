package org.cryptomator.cryptofs;

/**
 * Functions used from commons-lang
 */
final class StringUtils {

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

	public static String removeStart(String str, String remove) {
		if (str == null || remove == null) {
			return str;
		}
		if (str.startsWith(remove)) {
			return str.substring(remove.length());
		} else {
			return str;
		}
	}

}
