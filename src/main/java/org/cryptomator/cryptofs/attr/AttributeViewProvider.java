/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CryptoFileSystemComponent;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoFileSystemScoped;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.attribute.FileAttributeView;
import java.util.Optional;

@CryptoFileSystemScoped
public class AttributeViewProvider {

	private static final Logger LOG = LoggerFactory.getLogger(AttributeViewProvider.class);

	private final CryptoFileSystemComponent component;

	@Inject
	AttributeViewProvider(CryptoFileSystemComponent component) {
		this.component = component;
	}

	/**
	 * @param cleartextPath the unencrypted path to the file
	 * @param type          the Class object corresponding to the file attribute view
	 * @return a file attribute view of the specified type, or <code>null</code> if the attribute view type is not available
	 * @see Files#getFileAttributeView(java.nio.file.Path, Class, java.nio.file.LinkOption...)
	 */
	public <A extends FileAttributeView> A getAttributeView(CryptoPath cleartextPath, Class<A> type, LinkOption... options) {
		Optional<FileAttributeView> view = component.newFileAttributeViewComponent() //
				.cleartextPath(cleartextPath) //
				.viewType(type) //
				.linkOptions(options) //
				.build() //
				.attributeView();
		if (view.isPresent() && type.isInstance(view.get())) {
			return type.cast(view.get());
		} else {
			LOG.warn("Requested unsupported file attribute view: {}", type.getName());
			return null;
		}
	}

}
