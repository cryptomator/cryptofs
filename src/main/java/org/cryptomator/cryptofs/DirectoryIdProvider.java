/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;

@CryptoFileSystemScoped
class DirectoryIdProvider {

	private static final int MAX_CACHE_SIZE = 5000;

	private final LoadingCache<Path, String> ids;

	@Inject
	public DirectoryIdProvider(DirectoryIdLoader directoryIdLoader) {
		this.ids = Caffeine.newBuilder().maximumSize(MAX_CACHE_SIZE).build(directoryIdLoader);
	}

	public String load(Path dirFilePath) throws IOException {
		return ids.get(dirFilePath);
	}

	/**
	 * Removes the id currently associated with <code>dirFilePath</code> from cache. Useful during folder delete operations.
	 * This method has no effect if the content of the given dirFile is not currently cached.
	 * 
	 * @param dirFilePath The dirFile for which the cache should be deleted.
	 */
	public void delete(Path dirFilePath) {
		ids.invalidate(dirFilePath);
	}

	/**
	 * Transfers ownership from the id currently associated with <code>srcDirFilePath</code> to <code>dstDirFilePath</code>. Usefule during folder move operations.
	 * This method has no effect if the content of the source dirFile is not currently cached.
	 * 
	 * @param srcDirFilePath The dirFile that contained the cached id until now.
	 * @param dstDirFilePath The dirFile that will contain the id from now on.
	 */
	public void move(Path srcDirFilePath, Path dstDirFilePath) {
		String id = ids.getIfPresent(srcDirFilePath);
		if (id != null) {
			ids.put(dstDirFilePath, id);
			ids.invalidate(srcDirFilePath);
		}
	}


}
