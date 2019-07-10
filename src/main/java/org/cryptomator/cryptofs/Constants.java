/*******************************************************************************
 * Copyright (c) 2016, 2017 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

public final class Constants {

	public static final int VAULT_VERSION = 6;
	public static final String MASTERKEY_BACKUP_SUFFIX = ".bkup";

	static final String DATA_DIR_NAME = "d";
	static final String METADATA_DIR_NAME = "m";
	static final int SHORT_NAMES_MAX_LENGTH = 254; // length of a ciphertext filename before it gets shortened. It should be less than 260 (Windows MAX_PATH limit) and a multiple of 8 when the file extensions (4) and prefix (2) is subtracted.
	static final String ROOT_DIR_ID = "";

	static final int MAX_SYMLINK_LENGTH = 32767; // max path length on NTFS and FAT32: 32k-1

	static final String SEPARATOR = "/";

}
