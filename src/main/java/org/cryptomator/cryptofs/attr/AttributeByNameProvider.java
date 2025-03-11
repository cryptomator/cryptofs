/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import com.google.common.collect.ImmutableSortedMap;
import org.cryptomator.cryptofs.CryptoFileSystemScoped;
import org.cryptomator.cryptofs.CryptoPath;

import jakarta.inject.Inject;
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
import java.util.function.Function;
import java.util.function.Predicate;

import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toSet;

@CryptoFileSystemScoped
public class AttributeByNameProvider {

	private static final SortedMap<String, AttrGetter<?>> GETTERS = ImmutableSortedMap.<String, AttrGetter<?>>naturalOrder()
			// basic:
			.put("basic:lastModifiedTime", new AttrGetter<>("lastModifiedTime", BasicFileAttributes.class, BasicFileAttributes::lastModifiedTime)) //
			.put("basic:lastAccessTime", new AttrGetter<>("lastAccessTime", BasicFileAttributes.class, BasicFileAttributes::lastAccessTime)) //
			.put("basic:creationTime", new AttrGetter<>("creationTime", BasicFileAttributes.class, BasicFileAttributes::creationTime)) //
			.put("basic:isRegularFile", new AttrGetter<>("isRegularFile", BasicFileAttributes.class, BasicFileAttributes::isRegularFile)) //
			.put("basic:isDirectory", new AttrGetter<>("isDirectory", BasicFileAttributes.class, BasicFileAttributes::isDirectory)) //
			.put("basic:isSymbolicLink", new AttrGetter<>("isSymbolicLink", BasicFileAttributes.class, BasicFileAttributes::isSymbolicLink)) //
			.put("basic:isOther", new AttrGetter<>("isOther", BasicFileAttributes.class, BasicFileAttributes::isOther)) //
			.put("basic:size", new AttrGetter<>("size", BasicFileAttributes.class, BasicFileAttributes::size)) //
			.put("basic:fileKey", new AttrGetter<>("fileKey", BasicFileAttributes.class, BasicFileAttributes::fileKey)) //
			// dos:
			.put("dos:readOnly", new AttrGetter<>("readOnly", DosFileAttributes.class, DosFileAttributes::isReadOnly)) //
			.put("dos:hidden", new AttrGetter<>("hidden", DosFileAttributes.class, DosFileAttributes::isHidden)) //
			.put("dos:archive", new AttrGetter<>("archive", DosFileAttributes.class, DosFileAttributes::isArchive)) //
			.put("dos:system", new AttrGetter<>("system", DosFileAttributes.class, DosFileAttributes::isSystem)) //
			// posix:
			.put("posix:owner", new AttrGetter<>("owner", PosixFileAttributes.class, PosixFileAttributes::owner)) //
			.put("posix:group", new AttrGetter<>("group", PosixFileAttributes.class, PosixFileAttributes::group)) //
			.put("posix:permissions", new AttrGetter<>("permissions", PosixFileAttributes.class, PosixFileAttributes::permissions)) //
			.build();
	private static final Map<String, AttrSetter<?, ?>> SETTERS = Map.of( //
			"basic:lastModifiedTime", new AttrSetter<>(BasicFileAttributeView.class, FileTime.class, (view, lastModifiedTime) -> view.setTimes(lastModifiedTime, null, null)), //
			"basic:lastAccessTime", new AttrSetter<>(BasicFileAttributeView.class, FileTime.class, (view, lastAccessTime) -> view.setTimes(null, lastAccessTime, null)), //
			"basic:creationTime", new AttrSetter<>(BasicFileAttributeView.class, FileTime.class, (view, creationTime) -> view.setTimes(null, null, creationTime)), //
			"dos:readOnly", new AttrSetter<>(DosFileAttributeView.class, Boolean.class, DosFileAttributeView::setReadOnly), //
			"dos:hidden", new AttrSetter<>(DosFileAttributeView.class, Boolean.class, DosFileAttributeView::setHidden), //
			"dos:archive", new AttrSetter<>(DosFileAttributeView.class, Boolean.class, DosFileAttributeView::setArchive), //
			"dos:system", new AttrSetter<>(DosFileAttributeView.class, Boolean.class, DosFileAttributeView::setSystem), //
			"posix:owner", new AttrSetter<>(PosixFileAttributeView.class, UserPrincipal.class, PosixFileAttributeView::setOwner), //
			"posix:group", new AttrSetter<>(PosixFileAttributeView.class, GroupPrincipal.class, PosixFileAttributeView::setGroup), //
			"posix:permissions", new AttrSetter<>(PosixFileAttributeView.class, Set.class, PosixFileAttributeView::setPermissions) //
	);

	private final AttributeProvider attributeProvider;
	private final AttributeViewProvider attributeViewProvider;


	@Inject
	AttributeByNameProvider(AttributeProvider attributeProvider, AttributeViewProvider attributeViewProvider) {
		this.attributeProvider = attributeProvider;
		this.attributeViewProvider = attributeViewProvider;
	}

	public void setAttribute(CryptoPath cleartextPath, String attributeName, Object value, LinkOption... options) throws IOException {
		String normalizedAttributeName = normalizedAttributeName(attributeName);
		AttrSetter<?, ?> setter = SETTERS.get(normalizedAttributeName);
		if (setter == null) {
			throw new IllegalArgumentException("Unrecognized attribute name: " + attributeName);
		}
		setter.set(attributeViewProvider, cleartextPath, value, options);
	}

	public Map<String, Object> readAttributes(CryptoPath cleartextPath, String attributesString, LinkOption... options) throws IOException {
		if (attributesString.isEmpty()) {
			throw new IllegalArgumentException("No attributes specified");
		}
		Predicate<String> getterNameFilter = getterNameFilter(attributesString);
		Collection<AttrGetter<?>> getters = GETTERS.entrySet().stream() //
				.filter(entry -> getterNameFilter.test(entry.getKey())) //
				.<AttrGetter<?>>map(Entry::getValue) //
				.toList();
		return readAttributes(cleartextPath, getters, options);
	}

	private Map<String, Object> readAttributes(CryptoPath cleartextPath, Collection<AttrGetter<?>> getters, LinkOption... options) throws IOException {
		Map<String, Object> result = new HashMap<>();
		BasicFileAttributes attributes = null;
		for (AttrGetter<?> getter : getters) {
			if (attributes == null) {
				attributes = attributeProvider.readAttributes(cleartextPath, getter.type, options);
			}
			String key = getter.name;
			Object value = getter.get(attributes);
			result.put(key, value);
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

	private static class AttrSetter<T extends FileAttributeView, V> {

		@FunctionalInterface
		interface Setter<T extends FileAttributeView, V> {

			void set(T attributes, V value) throws IOException;
		}

		private final Class<T> type;
		private final Class<V> valueType;
		private final Setter<T, V> setter;

		public AttrSetter(Class<T> type, Class<V> valueType, Setter<T, V> setter) {
			this.type = type;
			this.valueType = valueType;
			this.setter = setter;
		}

		public void set(AttributeViewProvider provider, CryptoPath cleartextPath, Object value, LinkOption... options) throws IOException {
			T attrs = provider.getAttributeView(cleartextPath, type, options);
			setter.set(attrs, valueType.cast(value));
		}
	}

	private static class AttrGetter<T extends BasicFileAttributes> {

		private final String name;
		private final Class<T> type;
		private final Function<T, Object> getter;

		public AttrGetter(String name, Class<T> type, Function<T, Object> getter) {
			this.name = name;
			this.type = type;
			this.getter = getter;
		}

		public Object get(BasicFileAttributes attrs) {
			return getter.apply(type.cast(attrs));
		}

	}

}
