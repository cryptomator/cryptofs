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

	public static final int VAULT_VERSION = 7;
	public static final String MASTERKEY_BACKUP_SUFFIX = ".bkup";

	static final String DATA_DIR_NAME = "d";
	@Deprecated static final String METADATA_DIR_NAME = "m";
	static final int SHORT_NAMES_MAX_LENGTH = 222; // calculations done in https://github.com/cryptomator/cryptofs/issues/60
	static final String ROOT_DIR_ID = "";
	static final String CRYPTOMATOR_FILE_SUFFIX = ".c9r";
	static final String DEFLATED_FILE_SUFFIX = ".c9s";
	static final String DIR_FILE_NAME = "dir.c9r";
	static final String SYMLINK_FILE_NAME = "symlink.c9r";
	static final String CONTENTS_FILE_NAME = "contents.c9r";
	static final String INFLATED_FILE_NAME = "name.c9s";

	static final int MAX_SYMLINK_LENGTH = 32767; // max path length on NTFS and FAT32: 32k-1

	static final String SEPARATOR = "/";

}
