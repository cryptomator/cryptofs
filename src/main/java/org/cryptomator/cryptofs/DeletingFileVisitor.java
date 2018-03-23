/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

import static java.nio.file.attribute.PosixFilePermission.*;

class DeletingFileVisitor extends SimpleFileVisitor<Path> {

	public static final DeletingFileVisitor INSTANCE = new DeletingFileVisitor();

	private static final Set<PosixFilePermission> POSIX_PERMISSIONS_770 = EnumSet.of(OWNER_WRITE, OWNER_READ, OWNER_EXECUTE, GROUP_WRITE, GROUP_READ, GROUP_EXECUTE);

	private DeletingFileVisitor() {
	}

	@Override
	public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
		forceDeleteIfExists(file);
		return FileVisitResult.CONTINUE;
	}

	@Override
	public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
		forceDeleteIfExists(dir);
		return FileVisitResult.CONTINUE;
	}

	/**
	 * Tries to remove any write protection of the given file and tries to delete it afterwards.
	 * @param path Path ot a single file or directory. Will not be deleted recursively.
	 * @throws IOException exception thrown by delete. Any exceptions during removal of write protection will be ignored.
	 */
	static void forceDeleteIfExists(Path path) throws IOException {
		setWritableSilently(path);
		Files.deleteIfExists(path);
	}

	private static void setWritableSilently(Path path) {
		try {
			setWritable(path);
		} catch (IOException e) {
			// ignore
		}
	}

	private static void setWritable(Path path) throws IOException {
		DosFileAttributeView dosAttributes = Files.getFileAttributeView(path, DosFileAttributeView.class);
		PosixFileAttributeView posixAttributes = Files.getFileAttributeView(path, PosixFileAttributeView.class);
		if (dosAttributes != null) {
			dosAttributes.setReadOnly(false);
			dosAttributes.setSystem(false);
		}
		if (posixAttributes != null) {
			posixAttributes.setPermissions(POSIX_PERMISSIONS_770);
		}
	}

}
