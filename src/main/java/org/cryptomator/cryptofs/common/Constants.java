/*******************************************************************************
 * Copyright (c) 2016, 2017 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.common;

public final class Constants {

	private Constants() {
	}

	public static final int VAULT_VERSION = 8;
	public static final String BACKUP_SUFFIX = ".bkup";
	public static final String DATA_DIR_NAME = "d";
	public static final String ROOT_DIR_ID = "";
	public static final String RECOVERY_DIR_ID = "recovery";

	public static final String CRYPTOMATOR_FILE_SUFFIX = ".c9r";
	public static final String DEFLATED_FILE_SUFFIX = ".c9s";
	public static final String DIR_FILE_NAME = "dir.c9r";
	public static final String SYMLINK_FILE_NAME = "symlink.c9r";
	public static final String CONTENTS_FILE_NAME = "contents.c9r";
	public static final String INFLATED_FILE_NAME = "name.c9s";

	public static final int DEFAULT_SHORTENING_THRESHOLD = 220;
	public static final int MAX_SYMLINK_LENGTH = 32767; // max path length on NTFS and FAT32: 32k-1
	public static final int MAX_DIR_FILE_LENGTH = 36; // UUIDv4: hex-encoded 16 byte int + 4 hyphens = 36 ASCII chars

	public static final String SEPARATOR = "/";
	public static final String RECOVERY_DIR_NAME = "CRYPTOMATOR_RECOVERY";
}
