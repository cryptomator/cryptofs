/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.nio.file.attribute.PosixFilePermission.GROUP_READ;
import static java.nio.file.attribute.PosixFilePermission.GROUP_WRITE;
import static java.nio.file.attribute.PosixFilePermission.OTHERS_READ;
import static java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE;
import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;
import static java.nio.file.attribute.PosixFilePermission.OWNER_WRITE;
import static java.util.Arrays.asList;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Set;

class DeletingFileVisitor extends SimpleFileVisitor<Path> {

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
			posixAttributes.setPermissions(readWritePermissions());
		}
	}

	private Set<PosixFilePermission> readWritePermissions() {
		return new HashSet<>(asList( //
				OWNER_READ, OWNER_WRITE, //
				GROUP_READ, GROUP_WRITE, //
				OTHERS_READ, OTHERS_WRITE));
	}

}
