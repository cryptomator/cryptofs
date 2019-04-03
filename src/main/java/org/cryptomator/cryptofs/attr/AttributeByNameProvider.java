/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import com.google.common.base.Predicate;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoFileSystemScoped;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.LinkOption;
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

import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

@CryptoFileSystemScoped
public class AttributeByNameProvider {

	private static final SortedMap<String, AttributeGetterImpl<?>> GETTERS = new TreeMap<>();
	private static final SortedMap<String, AttributeSetterImpl<?, ?>> SETTERS = new TreeMap<>();

	private final AttributeProvider attributeProvider;
	private final AttributeViewProvider attributeViewProvider;

	static {
		// GETTERS:
		getter("basic:lastModifiedTime", BasicFileAttributes.class, BasicFileAttributes::lastModifiedTime);
		getter("basic:lastAccessTime", BasicFileAttributes.class, BasicFileAttributes::lastAccessTime);
		getter("basic:creationTime", BasicFileAttributes.class, BasicFileAttributes::creationTime);
		getter("basic:isRegularFile", BasicFileAttributes.class, BasicFileAttributes::isRegularFile);
		getter("basic:isDirectory", BasicFileAttributes.class, BasicFileAttributes::isDirectory);
		getter("basic:isSymbolicLink", BasicFileAttributes.class, BasicFileAttributes::isSymbolicLink);
		getter("basic:isOther", BasicFileAttributes.class, BasicFileAttributes::isOther);
		getter("basic:size", BasicFileAttributes.class, BasicFileAttributes::size);
		getter("basic:fileKey", BasicFileAttributes.class, BasicFileAttributes::fileKey);
		getter("dos:readOnly", DosFileAttributes.class, DosFileAttributes::isReadOnly);
		getter("dos:hidden", DosFileAttributes.class, DosFileAttributes::isHidden);
		getter("dos:archive", DosFileAttributes.class, DosFileAttributes::isArchive);
		getter("dos:system", DosFileAttributes.class, DosFileAttributes::isSystem);
		getter("posix:owner", PosixFileAttributes.class, PosixFileAttributes::owner);
		getter("posix:group", PosixFileAttributes.class, PosixFileAttributes::group);
		getter("posix:permissions", PosixFileAttributes.class, PosixFileAttributes::permissions);

		// SETTERS:
		setter("basic:lastModifiedTime", BasicFileAttributeView.class, FileTime.class, (view, lastModifiedTime) -> view.setTimes(lastModifiedTime, null, null));
		setter("basic:lastAccessTime", BasicFileAttributeView.class, FileTime.class, (view, lastAccessTime) -> view.setTimes(null, lastAccessTime, null));
		setter("basic:creationTime", BasicFileAttributeView.class, FileTime.class, (view, creationTime) -> view.setTimes(null, null, creationTime));
		setter("dos:readOnly", DosFileAttributeView.class, Boolean.class, DosFileAttributeView::setReadOnly);
		setter("dos:hidden", DosFileAttributeView.class, Boolean.class, DosFileAttributeView::setHidden);
		setter("dos:archive", DosFileAttributeView.class, Boolean.class, DosFileAttributeView::setArchive);
		setter("dos:system", DosFileAttributeView.class, Boolean.class, DosFileAttributeView::setSystem);
		setter("posix:owner", PosixFileAttributeView.class, UserPrincipal.class, PosixFileAttributeView::setOwner);
		setter("posix:group", PosixFileAttributeView.class, GroupPrincipal.class, PosixFileAttributeView::setGroup);
		setter("posix:permissions", PosixFileAttributeView.class, Set.class, PosixFileAttributeView::setPermissions);
	}

	private static <T extends BasicFileAttributes> void getter(String name, Class<T> type, AttributeGetter<T> getter) {
		String plainName = name.substring(name.indexOf(':') + 1);
		GETTERS.put(name, AttributeGetter.getter(plainName, type, getter));
	}

	private static <T extends BasicFileAttributeView, V> void setter(String name, Class<T> type, Class<V> valueType, AttributeSetter<T, V> setter) {
		SETTERS.put(name, AttributeSetter.setter(type, valueType, setter));
	}

	@Inject
	AttributeByNameProvider(AttributeProvider attributeProvider, AttributeViewProvider attributeViewProvider) {
		this.attributeProvider = attributeProvider;
		this.attributeViewProvider = attributeViewProvider;
	}

	@SuppressWarnings({"unchecked", "rawtypes"})
	public void setAttribute(CryptoPath cleartextPath, String attributeName, Object value, LinkOption... options) throws IOException {
		String normalizedAttributeName = normalizedAttributeName(attributeName);
		AttributeSetterImpl setter = SETTERS.get(normalizedAttributeName);
		if (setter == null) {
			throw new IllegalArgumentException("Unrecognized attribute name: " + attributeName);
		}
		FileAttributeView view = attributeViewProvider.getAttributeView(cleartextPath, setter.type(), options);
		setter.set(view, value);
	}

	public Map<String, Object> readAttributes(CryptoPath cleartextPath, String attributesString, LinkOption... options) throws IOException {
		if (attributesString.isEmpty()) {
			throw new IllegalArgumentException("No attributes specified");
		}
		Predicate<String> getterNameFilter = getterNameFilter(attributesString);
		@SuppressWarnings("rawtypes")
		Collection<AttributeGetterImpl> getters = GETTERS.entrySet().stream() //
				.filter(entry -> getterNameFilter.apply(entry.getKey())) //
				.map(Entry::getValue) //
				.collect(toList());
		return readAttributes(cleartextPath, getters, options);
	}

	@SuppressWarnings({"rawtypes", "unchecked"})
	private Map<String, Object> readAttributes(CryptoPath cleartextPath, Collection<AttributeGetterImpl> getters, LinkOption... options) throws IOException {
		Map<String, Object> result = new HashMap<>();
		BasicFileAttributes attributes = null;
		for (AttributeGetterImpl getter : getters) {
			if (attributes == null) {
				attributes = attributeProvider.readAttributes(cleartextPath, getter.type(), options);
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

	@FunctionalInterface
	private interface AttributeSetter<T extends FileAttributeView, V> {

		void set(T attributes, V value) throws IOException;

		static <T extends FileAttributeView, V> AttributeSetterImpl<T, V> setter(Class<T> type, Class<V> valueType, AttributeSetter setter) {
			return new AttributeSetterImpl(type, valueType, setter);
		}

	}

	private static class AttributeSetterImpl<T extends FileAttributeView, V> implements AttributeSetter<T, V> {

		private final Class<T> type;
		private final Class<V> valueType;
		private final AttributeSetter<T, V> setter;

		private AttributeSetterImpl(Class<T> type, Class<V> valueType, AttributeSetter<T, V> setter) {
			this.type = type;
			this.valueType = valueType;
			this.setter = setter;
		}

		public Class<T> type() {
			return type;
		}

		@Override
		public void set(T attributes, V value) throws IOException {
			setter.set(attributes, valueType.cast(value));
		}

	}

	@FunctionalInterface
	private interface AttributeGetter<T extends BasicFileAttributes> {

		Object read(T attributes);

		static <T extends BasicFileAttributes> AttributeGetterImpl<T> getter(String name, Class<T> type, AttributeGetter<T> getter) {
			return new AttributeGetterImpl(name, type, getter);
		}

	}

	private static class AttributeGetterImpl<T extends BasicFileAttributes> implements AttributeGetter<T> {

		private final String name;
		private final Class<T> type;
		private final AttributeGetter<T> getter;

		private AttributeGetterImpl(String name, Class<T> type, AttributeGetter<T> getter) {
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

		@Override
		public Object read(T attributes) {
			return getter.read(attributes);
		}

	}

}
