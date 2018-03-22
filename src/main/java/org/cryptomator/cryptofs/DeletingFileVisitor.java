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

import static java.nio.file.attribute.PosixFilePermission.*;

class DeletingFileVisitor extends SimpleFileVisitor<Path> {

	public static final DeletingFileVisitor INSTANCE = new DeletingFileVisitor();

	private static final EnumSet<PosixFilePermission> POSIX_PERMISSIONS_660 = EnumSet.of(OWNER_WRITE, OWNER_READ, GROUP_WRITE, GROUP_READ);

	private DeletingFileVisitor() {
	}

	@Override
	public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
		forceDelete(file);
		return FileVisitResult.CONTINUE;
	}

	@Override
	public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
		forceDelete(dir);
		return FileVisitResult.CONTINUE;
	}

	private void forceDelete(Path path) throws IOException {
		setWritableSilently(path);
		Files.deleteIfExists(path);
	}

	private void setWritableSilently(Path path) {
		try {
			setWritable(path);
		} catch (IOException e) {
			// ignore
		}
	}

	private void setWritable(Path path) throws IOException {
		DosFileAttributeView dosAttributes = Files.getFileAttributeView(path, DosFileAttributeView.class);
		PosixFileAttributeView posixAttributes = Files.getFileAttributeView(path, PosixFileAttributeView.class);
		if (dosAttributes != null) {
			dosAttributes.setReadOnly(false);
			dosAttributes.setSystem(false);
		}
		if (posixAttributes != null) {
			posixAttributes.setPermissions(POSIX_PERMISSIONS_660);
		}
	}

}
