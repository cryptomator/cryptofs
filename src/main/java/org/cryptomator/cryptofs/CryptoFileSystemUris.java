/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static org.apache.commons.lang3.StringUtils.defaultIfEmpty;
import static org.apache.commons.lang3.StringUtils.removeStart;
import static org.apache.commons.lang3.SystemUtils.IS_OS_WINDOWS;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystems;
import java.nio.file.Path;

import org.apache.commons.lang3.StringUtils;

/**
 * <p>
 * Utility to handle {@link URI}s used by the {@link CryptoFileSystemProvider}.
 * <p>
 * CryptoFileSystem URIs are hierachical URIs with the scheme <i>cryptomator</i>, the absolute path to a vault as path and an optional
 * fragment part which is the path to a directory or file inside the vault. As hierarchical URIs have the syntax
 * <blockquote>
 * [<i>scheme</i><b>{@code :}</b>][<b>{@code //}</b><i>authority</i>][<i>path</i>][<b>{@code ?}</b><i>query</i>][<b>{@code #}</b><i>fragment</i>]
 * </blockquote>
 * <p>
 * this leads to cryptomator URIs of the form
 * <blockquote>
 * <i>cryptomator</i><b>{@code :}</b><i>/absolutePathToVault</i>[<b>{@code #}</b><i>pathInsideVault</i>]
 * </blockquote>
 * 
 * @author Markus Kreusch
 */
public class CryptoFileSystemUris {

	public static final String URI_SCHEME = "cryptomator";

	private CryptoFileSystemUris() {}

	/**
	 * Constructs a CryptoFileSystem URI by using the given absolute path to a vault and constructing a path inside the vault from components.
	 * 
	 * @param absolutePathToVault absolute path to the vault
	 * @param pathComponentsInsideVault path components to node inside the vault
	 * @throws IllegalArgumentException if the provided absolutePathToVault is not absolute
	 */
	public static URI createUri(Path absolutePathToVault, String... pathComponentsInsideVault) {
		if (!absolutePathToVault.isAbsolute()) {
			throw new IllegalArgumentException(absolutePathToVault + " is not absolute");
		}
		try {
			return new URI(URI_SCHEME, null, StringUtils.prependIfMissing(absolutePathToVault.toString(), "/"), "/" + String.join("/", pathComponentsInsideVault));
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("Can not create URI from given path.", e);
		}
	}

	static ParsedUri parseUri(URI uri) {
		return new ParsedUri(uri);
	}

	static class ParsedUri {

		private final Path pathToVault;
		private final String pathInsideVault;

		public ParsedUri(URI uri) {
			validate(uri);
			if (IS_OS_WINDOWS) {
				pathToVault = FileSystems.getDefault().getPath(removeStart(uri.getPath(), "/"));
			} else {
				pathToVault = FileSystems.getDefault().getPath(uri.getPath());
			}
			pathInsideVault = defaultIfEmpty(uri.getFragment(), "/");
		}

		private void validate(URI uri) {
			if (!URI_SCHEME.equals(uri.getScheme())) {
				throw new IllegalArgumentException("URI must have " + URI_SCHEME + " scheme");
			}
			if (uri.getPath() == null) {
				throw new IllegalArgumentException("URI must not have a path");
			}
			if (uri.getQuery() != null) {
				throw new IllegalArgumentException("URI must not have a query part");
			}
			if (uri.getAuthority() != null) {
				throw new IllegalArgumentException("URI must not have an authority part");
			}
		}

		public Path pathToVault() {
			return pathToVault;
		}

		public String pathInsideVault() {
			return pathInsideVault;
		}

	}

}
