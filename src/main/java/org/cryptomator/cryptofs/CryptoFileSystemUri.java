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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
 * <i>cryptomator</i><b>{@code :}//</b><i>file:%2F%2Fpath%2Fto%2Fvault%2Fas%2Furi</i><b>/</b><i>path/inside/vault</i>
 * </blockquote>
 * 
 * @author Markus Kreusch
 */
public class CryptoFileSystemUri {

	public static final String URI_SCHEME = "cryptomator";
	private static final Pattern UNC_URI_PATTERN = Pattern.compile("^file://[^@/]+(@SSL)?(@[0-9]+)?.*");

	private final Path pathToVault;
	private final String pathInsideVault;

	private CryptoFileSystemUri(URI uri) {
		validate(uri);
		pathToVault = uncCompatibleUriToPath(URI.create(uri.getAuthority()));
		pathInsideVault = uri.getPath();
	}

	/**
	 * Creates Path from the given URI. On Windows this will recognize UNC paths.
	 * 
	 * @param uri <code>file:///file/path</code> or <code>file://server@SSL@123/actual/file/path</code>
	 * @return <code>/file/path</code> or <code>\\server@SSL@123\actual\file\path</code>
	 */
	// visible for testing
	static Path uncCompatibleUriToPath(URI uri) {
		String in = uri.toString();
		Matcher m = UNC_URI_PATTERN.matcher(in);
		if (m.find() && (m.group(1) != null || m.group(2) != null)) { // this is an UNC path!
			String out = in.substring("file:".length()).replace('/', '\\');
			return Paths.get(out);
		} else {
			return Paths.get(uri);
		}
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
