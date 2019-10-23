package org.cryptomator.cryptofs.common;

/**
 * Filename prefix as defined <a href="https://github.com/cryptomator/cryptofs/issues/38">issue 38</a>.
 */
public enum CiphertextFileType {
	FILE,
	DIRECTORY,
	SYMLINK;
}
