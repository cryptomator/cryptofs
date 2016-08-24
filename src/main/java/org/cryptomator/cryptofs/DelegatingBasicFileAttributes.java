/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

interface DelegatingBasicFileAttributes extends BasicFileAttributes {

	BasicFileAttributes getDelegate();

	@Override
	default FileTime lastModifiedTime() {
		return getDelegate().lastModifiedTime();
	}

	@Override
	default FileTime lastAccessTime() {
		return getDelegate().lastAccessTime();
	}

	@Override
	default FileTime creationTime() {
		return getDelegate().creationTime();
	}

	@Override
	default boolean isRegularFile() {
		return getDelegate().isRegularFile();
	}

	@Override
	default boolean isDirectory() {
		return getDelegate().isDirectory();
	}

	@Override
	default boolean isSymbolicLink() {
		return getDelegate().isSymbolicLink();
	}

	@Override
	default boolean isOther() {
		return getDelegate().isOther();
	}

	@Override
	default long size() {
		return getDelegate().size();
	}

	@Override
	default Object fileKey() {
		return getDelegate().fileKey();
	}

}
