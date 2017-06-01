/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * <p>
 * Utility to handle {@link URI}s used by the {@link CryptoFileSystemProvider}.
 * <p>
 * CryptoFileSystem URIs are hierachical URIs with the scheme <i>cryptomator</i>, the absolute path to a vault in URI representation as Authority and
 * a path which is the path to a directory or file inside the vault. As hierarchical URIs have the syntax
 * <blockquote>
 * [<i>scheme</i><b>{@code :}</b>][<b>{@code //}</b><i>authority</i><b>{@code /}</b>][<i>path</i>][<b>{@code ?}</b><i>query</i>][<b>{@code #}</b><i>fragment</i>]
 * </blockquote>
 * <p>
 * this leads to cryptomator URIs of the form
 * <blockquote>
 * <i>cryptomator</i><b>{@code :}//</b><i>file:<tt>%2F%2F</tt>path<tt>%2F</tt>to<tt>%2F</tt>vault<tt>%2F</tt>as<tt>%2F</tt>uri</i><b>/</b><i>path/inside/vault</i>
 * </blockquote>
 * 
 * @author Markus Kreusch
 */
public class CryptoFileSystemUri {

	public static final String URI_SCHEME = "cryptomator";

	private final Path pathToVault;
	private final String pathInsideVault;

	private CryptoFileSystemUri(URI uri) {
		validate(uri);
		pathToVault = Paths.get(URI.create(uri.getAuthority()));
		pathInsideVault = uri.getPath();
	}

	/**
	 * Constructs a CryptoFileSystem URI by using the given absolute path to a vault and constructing a path inside the vault from components.
	 * 
	 * @param pathToVault path to the vault
	 * @param pathComponentsInsideVault path components to node inside the vault
	 */
	public static URI create(Path pathToVault, String... pathComponentsInsideVault) {
		try {
			return new URI(URI_SCHEME, pathToVault.toUri().toString(), "/" + String.join("/", pathComponentsInsideVault), null, null);
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("Can not create URI from given input", e);
		}
	}

	/**
	 * Decodes the path to a vault and the path inside a vault from the given URI.
	 * 
	 * @param uri A valid CryptoFileSystem URI
	 * @return Decoded URI components
	 * @throws IllegalArgumentException If the given URI does not comply with the CryptoFileSystem URI standard.
	 */
	static CryptoFileSystemUri parse(URI uri) throws IllegalArgumentException {
		return new CryptoFileSystemUri(uri);
	}

	private static void validate(URI uri) {
		if (!URI_SCHEME.equals(uri.getScheme())) {
			throw new IllegalArgumentException("URI must have " + URI_SCHEME + " scheme");
		}
		if (uri.getAuthority() == null) {
			throw new IllegalArgumentException("URI must have an authority");
		}
		if (uri.getPath() == null || uri.getPath().isEmpty()) {
			throw new IllegalArgumentException("URI must have a path");
		}
		if (uri.getQuery() != null) {
			throw new IllegalArgumentException("URI must not have a query part");
		}
		if (uri.getFragment() != null) {
			throw new IllegalArgumentException("URI must not have a fragment part");
		}
	}

	/* GETTER */

	public Path pathToVault() {
		return pathToVault;
	}

	public String pathInsideVault() {
		return pathInsideVault;
	}

}
