/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CryptoFileSystemScoped;
import org.cryptomator.cryptofs.CryptoPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.attribute.FileAttributeView;
import java.util.Optional;

@CryptoFileSystemScoped
public class AttributeViewProvider {

	private static final Logger LOG = LoggerFactory.getLogger(AttributeViewProvider.class);

	private final AttributeViewComponent.Factory attrViewComponentFactory;

	@Inject
	AttributeViewProvider(AttributeViewComponent.Factory attrViewComponentFactory) {
		this.attrViewComponentFactory = attrViewComponentFactory;
	}

	/**
	 * @param cleartextPath the unencrypted path to the file
	 * @param type the Class object corresponding to the file attribute view
	 * @return a file attribute view of the specified type, or <code>null</code> if the attribute view type is not available
	 * @see Files#getFileAttributeView(java.nio.file.Path, Class, java.nio.file.LinkOption...)
	 */
	public <A extends FileAttributeView> A getAttributeView(CryptoPath cleartextPath, Class<A> type, LinkOption... options) {
		Optional<FileAttributeView> view = attrViewComponentFactory.create(cleartextPath, type, options).attributeView();
		if (view.isPresent() && type.isInstance(view.get())) {
			return type.cast(view.get());
		} else {
			LOG.warn("Requested unsupported file attribute view: {}", type.getName());
			return null;
		}
	}

}
