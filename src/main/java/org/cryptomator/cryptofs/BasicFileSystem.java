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
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.WatchService;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Only ONE root and ONE filestore
 */
abstract class BasicFileSystem extends FileSystem {

	private static final String SEPARATOR = "/";
	private final BasicPath root;
	private final BasicPath emptyPath;

	public BasicFileSystem() {
		this.root = new BasicPath(this, Collections.emptyList(), true);
		this.emptyPath = new BasicPath(this, Collections.emptyList(), false);
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public String getSeparator() {
		return SEPARATOR;
	}

	public BasicPath getEmptyPath() {
		return emptyPath;
	}

	public BasicPath getRootDirectory() {
		return root;
	}

	@Override
	public Iterable<Path> getRootDirectories() {
		return Collections.singleton(getRootDirectory());
	}

	public abstract FileStore getFileStore();

	@Override
	public Iterable<FileStore> getFileStores() {
		return Collections.singleton(getFileStore());
	}

	@Override
	public BasicPath getPath(String first, String... more) {
		List<String> elements = new ArrayList<>();
		elements.addAll(splitPath(first));
		elements.addAll(Arrays.stream(more).map(this::splitPath).flatMap(List::stream).collect(Collectors.toList()));
		boolean isAbsolute = first.startsWith(getSeparator());
		return new BasicPath(this, elements, isAbsolute);
	}

	private List<String> splitPath(String path) {
		StringTokenizer tokenizer = new StringTokenizer(path, getSeparator());
		List<String> result = new ArrayList<>();
		while (tokenizer.hasMoreTokens()) {
			result.add(tokenizer.nextToken());
		}
		return result;
	}

	public URI toUri(Path path) {
		try {
			return new URI(provider().getScheme(), null, path.toAbsolutePath().normalize().toString(), null);
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("Path does not conform to RFC 3986, section 3.3", e);
		}
	}

	@Override
	public PathMatcher getPathMatcher(String syntaxAndPattern) {
		final Pattern pattern;
		if (syntaxAndPattern.startsWith("glob:")) {
			pattern = Pattern.compile(GlobToRegex.toRegex(syntaxAndPattern.substring(5), "/"));
		} else if (syntaxAndPattern.startsWith("regex:")) {
			pattern = Pattern.compile(syntaxAndPattern.substring(6));
		} else {
			throw new UnsupportedOperationException();
		}
		return getPathMatcher(pattern);
	}

	protected PathMatcher getPathMatcher(Pattern pattern) {
		return new PathMatcher() {
			@Override
			public boolean matches(Path path) {
				return pattern.matcher(path.toString()).matches();
			}
		};
	}

	@Override
	public UserPrincipalLookupService getUserPrincipalLookupService() {
		throw new UnsupportedOperationException();
	}

	@Override
	public WatchService newWatchService() throws IOException {
		throw new UnsupportedOperationException();
	}

}
