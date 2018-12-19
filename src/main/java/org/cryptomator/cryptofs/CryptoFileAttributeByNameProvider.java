/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.UserPrincipal;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.function.Function;

import javax.inject.Inject;

import com.google.common.base.Predicate;

@PerFileSystem
class CryptoFileAttributeByNameProvider {

	private static final SortedMap<String, AttributeGetter<?>> GETTERS = new TreeMap<>();
	static {
		attribute("basic:lastModifiedTime", BasicFileAttributes.class, BasicFileAttributes::lastModifiedTime);
		attribute("basic:lastAccessTime", BasicFileAttributes.class, BasicFileAttributes::lastAccessTime);
		attribute("basic:creationTime", BasicFileAttributes.class, BasicFileAttributes::creationTime);
		attribute("basic:isRegularFile", BasicFileAttributes.class, BasicFileAttributes::isRegularFile);
		attribute("basic:isDirectory", BasicFileAttributes.class, BasicFileAttributes::isDirectory);
		attribute("basic:isSymbolicLink", BasicFileAttributes.class, BasicFileAttributes::isSymbolicLink);
		attribute("basic:isOther", BasicFileAttributes.class, BasicFileAttributes::isOther);
		attribute("basic:size", BasicFileAttributes.class, BasicFileAttributes::size);
		attribute("basic:fileKey", BasicFileAttributes.class, BasicFileAttributes::fileKey);

		attribute("dos:readOnly", DosFileAttributes.class, DosFileAttributes::isReadOnly);
		attribute("dos:hidden", DosFileAttributes.class, DosFileAttributes::isHidden);
		attribute("dos:archive", DosFileAttributes.class, DosFileAttributes::isArchive);
		attribute("dos:system", DosFileAttributes.class, DosFileAttributes::isSystem);

		attribute("posix:owner", PosixFileAttributes.class, PosixFileAttributes::owner);
		attribute("posix:group", PosixFileAttributes.class, PosixFileAttributes::group);
		attribute("posix:permissions", PosixFileAttributes.class, PosixFileAttributes::permissions);
	}

	private static final SortedMap<String, AttributeSetter<?, ?>> SETTERS = new TreeMap<>();
	static {
		attribute("basic:lastModifiedTime", BasicFileAttributeView.class, FileTime.class, (view, lastModifiedTime) -> view.setTimes(lastModifiedTime, null, null));
		attribute("basic:lastAccessTime", BasicFileAttributeView.class, FileTime.class, (view, lastAccessTime) -> view.setTimes(null, lastAccessTime, null));
		attribute("basic:creationTime", BasicFileAttributeView.class, FileTime.class, (view, creationTime) -> view.setTimes(null, null, creationTime));

		attribute("dos:readOnly", DosFileAttributeView.class, Boolean.class, DosFileAttributeView::setReadOnly);
		attribute("dos:hidden", DosFileAttributeView.class, Boolean.class, DosFileAttributeView::setHidden);
		attribute("dos:archive", DosFileAttributeView.class, Boolean.class, DosFileAttributeView::setArchive);
		attribute("dos:system", DosFileAttributeView.class, Boolean.class, DosFileAttributeView::setSystem);

		attribute("posix:owner", PosixFileAttributeView.class, UserPrincipal.class, PosixFileAttributeView::setOwner);
		attribute("posix:group", PosixFileAttributeView.class, GroupPrincipal.class, PosixFileAttributeView::setGroup);
		attribute("posix:permissions", PosixFileAttributeView.class, Set.class, PosixFileAttributeView::setPermissions);
	}

	private static <T extends BasicFileAttributes> void attribute(String name, Class<T> type, Function<T, ?> getter) {
		String plainName = name.substring(name.indexOf(':') + 1);
		GETTERS.put(name, new AttributeGetter<>(plainName, type, getter));
	}

	private static <T extends BasicFileAttributeView, V> void attribute(String name, Class<T> type, Class<V> valueType, BiConsumerThrowingException<T, V, IOException> setter) {
		SETTERS.put(name, new AttributeSetter<>(type, valueType, setter));
	}

	private final CryptoFileAttributeProvider cryptoFileAttributeProvider;
	private final CryptoFileAttributeViewProvider cryptoFileAttributeViewProvider;

	@Inject
	public CryptoFileAttributeByNameProvider(CryptoFileAttributeProvider cryptoFileAttributeProvider, CryptoFileAttributeViewProvider cryptoFileAttributeViewProvider) {
		this.cryptoFileAttributeProvider = cryptoFileAttributeProvider;
		this.cryptoFileAttributeViewProvider = cryptoFileAttributeViewProvider;
	}

	@SuppressWarnings({"unchecked", "rawtypes"})
	public void setAttribute(CryptoPath cleartextPath, String attributeName, Object value) throws IOException {
		String normalizedAttributeName = normalizedAttributeName(attributeName);
		AttributeSetter setter = SETTERS.get(normalizedAttributeName);
		if (setter == null) {
			throw new IllegalArgumentException("Unrecognized attribute name: " + attributeName);
		}
		FileAttributeView view = cryptoFileAttributeViewProvider.getAttributeView(cleartextPath, setter.type());
		setter.set(view, value);
	}

	public Map<String, Object> readAttributes(CryptoPath cleartextPath, String attributesString) throws IOException {
		if (attributesString.isEmpty()) {
			throw new IllegalArgumentException("No attributes specified");
		}
		Predicate<String> getterNameFilter = getterNameFilter(attributesString);
		@SuppressWarnings("rawtypes")
		Collection<AttributeGetter> getters = GETTERS.entrySet().stream() //
				.filter(entry -> getterNameFilter.apply(entry.getKey())) //
				.map(Entry::getValue) //
				.collect(toList());
		return readAttributes(cleartextPath, getters);
	}

	@SuppressWarnings({"rawtypes", "unchecked"})
	private Map<String, Object> readAttributes(CryptoPath cleartextPath, Collection<AttributeGetter> getters) throws IOException {
		Map<String, Object> result = new HashMap<>();
		BasicFileAttributes attributes = null;
		for (AttributeGetter getter : getters) {
			if (attributes == null) {
				attributes = cryptoFileAttributeProvider.readAttributes(cleartextPath, getter.type());
			}
			String name = getter.name();
			result.put(name, getter.read(attributes));
		}
		return result;
	}

	private String normalizedAttributeName(String attributeName) {
		if (attributeName.indexOf(':') == -1) {
			return "basic:" + attributeName;
		} else {
			return attributeName;
		}
	}

	private Predicate<String> getterNameFilter(String attributesString) {
		String viewName = viewName(attributesString);
		Set<String> attributeNames = attributeNames(viewName, attributesString);
		if (attributeNames.contains("*")) {
			String prefix = viewName + ":";
			return value -> value.startsWith(prefix);
		} else {
			return attributeNames::contains;
		}
	}

	private String viewName(String attributes) {
		int firstColon = attributes.indexOf(':');
		if (firstColon == -1) {
			return "basic";
		} else {
			return attributes.substring(0, firstColon);
		}
	}

	private Set<String> attributeNames(String viewName, String attributeString) {
		int firstColon = attributeString.indexOf(':');
		String attributeNames;
		if (firstColon == -1) {
			attributeNames = attributeString;
		} else {
			attributeNames = attributeString.substring(firstColon + 1);
		}
		return stream(attributeNames.split(",")).map(name -> {
			if ("*".equals(name)) {
				return "*";
			} else {
				return viewName + ":" + name;
			}
		}).collect(toSet());
	}

	private static class AttributeSetter<T extends FileAttributeView, V> {

		private final Class<T> type;
		private final Class<V> valueType;
		private final BiConsumerThrowingException<T, V, IOException> setter;

		private AttributeSetter(Class<T> type, Class<V> valueType, BiConsumerThrowingException<T, V, IOException> setter) {
			this.type = type;
			this.valueType = valueType;
			this.setter = setter;
		}

		public Class<T> type() {
			return type;
		}

		public void set(T attributes, Object value) throws IOException {
			setter.accept(attributes, valueType.cast(value));
		}

	}

	private static class AttributeGetter<T extends BasicFileAttributes> {

		private final String name;
		private final Class<T> type;
		private final Function<T, ?> getter;

		private AttributeGetter(String name, Class<T> type, Function<T, ?> getter) {
			this.name = name;
			this.type = type;
			this.getter = getter;
		}

		public String name() {
			return name;
		}

		public Class<T> type() {
			return type;
		}

		public Object read(T attributes) {
			return getter.apply(attributes);
		}

	}

}
