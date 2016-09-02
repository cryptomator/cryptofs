/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.ProviderMismatchException;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * A path based on a singleton root per fileSystem.
 */
class BasicPath implements Path {

	private static final String CURRENT_DIR = ".";
	private static final String PARENT_DIR = "..";

	private final BasicFileSystem fileSystem;
	private final List<String> elements;
	private final boolean absolute;

	public BasicPath(BasicFileSystem fileSystem, List<String> elements, boolean absolute) {
		this.fileSystem = fileSystem;
		this.elements = Collections.unmodifiableList(elements);
		this.absolute = absolute;
	}

	static BasicPath cast(Path path) {
		if (path instanceof BasicPath) {
			return (BasicPath) path;
		} else {
			throw new ProviderMismatchException();
		}
	}

	@Override
	public BasicFileSystem getFileSystem() {
		return fileSystem;
	}

	@Override
	public boolean isAbsolute() {
		return absolute;
	}

	@Override
	public Path getRoot() {
		return absolute ? fileSystem.getRootDirectory() : null;
	}

	@Override
	public Path getFileName() {
		int elementCount = getNameCount();
		if (elementCount == 0) {
			return null;
		} else {
			return getName(elementCount - 1);
		}
	}

	@Override
	public Path getParent() {
		int elementCount = getNameCount();
		if (elementCount > 1) {
			List<String> elems = elements.subList(0, elementCount - 1);
			return createPath(fileSystem, elems, absolute);
		} else if (elementCount == 1 && isAbsolute()) {
			return getRoot();
		} else {
			return null;
		}
	}

	@Override
	public int getNameCount() {
		return elements.size();
	}

	@Override
	public Path getName(int index) {
		return subpath(index, index + 1);
	}

	@Override
	public BasicPath subpath(int beginIndex, int endIndex) {
		return createPath(fileSystem, elements.subList(beginIndex, endIndex), false);
	}

	/**
	 * @param fileSystem The filesystem this path refers to.
	 * @param elements The components of the path ordered from root to leaf.
	 * @return New (or cached) path instance.
	 */
	protected BasicPath createPath(BasicFileSystem fileSystem, List<String> elements, boolean absolute) {
		return new BasicPath(fileSystem, elements, absolute);
	}

	@Override
	public boolean startsWith(Path path) {
		BasicPath other = cast(path);
		boolean matchesAbsolute = this.isAbsolute() == other.isAbsolute();
		if (matchesAbsolute && other.elements.size() <= this.elements.size()) {
			return this.elements.subList(0, other.elements.size()).equals(other.elements);
		} else {
			return false;
		}
	}

	@Override
	public boolean startsWith(String other) {
		return startsWith(fileSystem.getPath(other));
	}

	@Override
	public boolean endsWith(Path path) {
		BasicPath other = cast(path);
		if (other.elements.size() <= this.elements.size()) {
			return this.elements.subList(this.elements.size() - other.elements.size(), this.elements.size()).equals(other.elements);
		} else {
			return false;
		}
	}

	@Override
	public boolean endsWith(String other) {
		return endsWith(fileSystem.getPath(other));
	}

	@Override
	public BasicPath normalize() {
		LinkedList<String> normalized = new LinkedList<>();
		for (String elem : elements) {
			String lastElem = normalized.peekLast();
			if (elem.isEmpty() || CURRENT_DIR.equals(elem)) {
				continue;
			} else if (PARENT_DIR.equals(elem) && lastElem != null && !PARENT_DIR.equals(lastElem)) {
				normalized.removeLast();
			} else {
				normalized.add(elem);
			}
		}
		return createPath(fileSystem, normalized, absolute);
	}

	@Override
	public Path resolve(Path path) {
		BasicPath other = cast(path);
		if (other.isAbsolute()) {
			return other;
		} else {
			List<String> joined = new ArrayList<>();
			joined.addAll(this.elements);
			joined.addAll(other.elements);
			return createPath(fileSystem, joined, absolute);
		}
	}

	@Override
	public Path resolve(String other) {
		return resolve(fileSystem.getPath(other));
	}

	@Override
	public Path resolveSibling(Path other) {
		final Path parent = getParent();
		if (parent == null || other.isAbsolute()) {
			return other;
		} else {
			return parent.resolve(other);
		}
	}

	@Override
	public Path resolveSibling(String other) {
		return resolveSibling(fileSystem.getPath(other));
	}

	@Override
	public Path relativize(Path path) {
		BasicPath normalized = this.normalize();
		BasicPath other = cast(path).normalize();
		if (normalized.isAbsolute() == other.isAbsolute()) {
			int commonPrefix = countCommonPrefixElements(normalized, other);
			int stepsUp = this.getNameCount() - commonPrefix;
			List<String> elems = new ArrayList<>();
			elems.addAll(Collections.nCopies(stepsUp, PARENT_DIR));
			elems.addAll(other.elements.subList(commonPrefix, other.getNameCount()));
			return createPath(fileSystem, elems, false);
		} else {
			throw new IllegalArgumentException("Can't relativize an absolute path relative to a relative path.");
		}
	}

	private int countCommonPrefixElements(BasicPath p1, BasicPath p2) {
		int n = Math.min(p1.getNameCount(), p2.getNameCount());
		for (int i = 0; i < n; i++) {
			if (!p1.elements.get(i).equals(p2.elements.get(i))) {
				return i;
			}
		}
		return n;
	}

	@Override
	public URI toUri() {
		return fileSystem.toUri(this);
	}

	@Override
	public Path toAbsolutePath() {
		if (isAbsolute()) {
			return this;
		} else {
			return createPath(fileSystem, elements, true);
		}
	}

	@Override
	public Path toRealPath(LinkOption... options) throws IOException {
		return toAbsolutePath();
	}

	@Override
	public File toFile() {
		throw new UnsupportedOperationException();
	}

	@Override
	public WatchKey register(WatchService watcher, WatchEvent.Kind<?>[] events, WatchEvent.Modifier... modifiers) throws IOException {
		throw new UnsupportedOperationException("Method not implemented.");
	}

	@Override
	public WatchKey register(WatchService watcher, WatchEvent.Kind<?>... events) throws IOException {
		throw new UnsupportedOperationException("Method not implemented.");
	}

	@Override
	public Iterator<Path> iterator() {
		return new Iterator<Path>() {

			private int idx = 0;

			@Override
			public boolean hasNext() {
				return idx < getNameCount();
			}

			@Override
			public Path next() {
				return getName(idx++);
			}
		};
	}

	@Override
	public int compareTo(Path path) {
		BasicPath other = (BasicPath) path;
		if (this.isAbsolute() != other.isAbsolute()) {
			return this.isAbsolute() ? -1 : 1;
		}
		for (int i = 0; i < Math.min(this.getNameCount(), other.getNameCount()); i++) {
			int result = this.elements.get(i).compareTo(other.elements.get(i));
			if (result != 0) {
				return result;
			}
		}
		return this.getNameCount() - other.getNameCount();
	}

	@Override
	public int hashCode() {
		int hash = 0;
		hash = 31 * hash + fileSystem.hashCode();
		hash = 31 * hash + elements.hashCode();
		hash = 31 * hash + (absolute ? 1 : 0);
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof BasicPath) {
			BasicPath other = (BasicPath) obj;
			return this.fileSystem.equals(other.fileSystem) //
					&& this.compareTo(other) == 0;
		} else {
			return false;
		}
	}

	@Override
	public String toString() {
		String sep = fileSystem.getSeparator();
		String prefix = isAbsolute() ? sep : "";
		return prefix + String.join(sep, elements);
	}

}
