package org.cryptomator.cryptofs;

/**
 * Filename prefix as defined <a href="https://github.com/cryptomator/cryptofs/issues/38">issue 38</a>.
 */
public enum CiphertextFileType {
	FILE,
	DIRECTORY,
	SYMLINK;
}
