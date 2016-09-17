/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.nio.file.attribute.DosFileAttributes;

interface DelegatingDosFileAttributes extends DelegatingBasicFileAttributes, DosFileAttributes {

	@Override
	DosFileAttributes getDelegate();

	@Override
	default boolean isReadOnly() {
		return getDelegate().isReadOnly();
	}

	@Override
	default boolean isHidden() {
		return getDelegate().isHidden();
	}

	@Override
	default boolean isArchive() {
		return getDelegate().isArchive();
	}

	@Override
	default boolean isSystem() {
		return getDelegate().isSystem();
	}

}
