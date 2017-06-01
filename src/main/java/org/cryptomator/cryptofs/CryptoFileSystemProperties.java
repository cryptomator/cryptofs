/*******************************************************************************
 * Copyright (c) 2016 Markus Kreusch and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Markus Kreusch - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableSet;

import java.net.URI;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import org.apache.commons.lang3.StringUtils;

/**
 * Properties to pass to
 * <ul>
 * <li>{@link FileSystems#newFileSystem(URI, Map)} or
 * <li>{@link CryptoFileSystemProvider#newFileSystem(Path, CryptoFileSystemProperties)}.
 * </ul>
 * 
 * @author Markus Kreusch
 */
public class CryptoFileSystemProperties extends AbstractMap<String, Object> {

	/**
	 * Key identifying the passphrase for an encrypted vault.
	 */
	public static final String PROPERTY_PASSPHRASE = "passphrase";

	/**
	 * Key identifying the name of the masterkey file located inside the vault directory.
	 * 
	 * @since 1.1.0
	 */
	public static final String PROPERTY_MASTERKEY_FILENAME = "masterkeyFilename";

	static final String DEFAULT_MASTERKEY_FILENAME = "masterkey.cryptomator";

	/**
	 * Key identifying the filesystem flags.
	 * 
	 * @since 1.3.0
	 */
	public static final String PROPERTY_FILESYSTEM_FLAGS = "flags";

	static final Set<FileSystemFlags> DEFAULT_FILESYSTEM_FLAGS = unmodifiableSet(EnumSet.of(FileSystemFlags.INIT_IMPLICITLY));

	public enum FileSystemFlags {
		/**
		 * If present, the vault is opened in read-only mode.
		 */
		READONLY,

		/**
		 * If present, the vault structure will implicitly get initialized upon filesystem creation.
		 * 
		 * @deprecated Will get removed in version 2.0.0. Use {@link CryptoFileSystemProvider#initialize(Path, String, CharSequence)} explicitly.
		 */
		@Deprecated INIT_IMPLICITLY
	};

	private final Set<Entry<String, Object>> entries;

	private CryptoFileSystemProperties(Builder builder) {
		this.entries = unmodifiableSet(new HashSet<>(asList( //
				entry(PROPERTY_PASSPHRASE, builder.passphrase), //
				entry(PROPERTY_FILESYSTEM_FLAGS, builder.flags), //
				entry(PROPERTY_MASTERKEY_FILENAME, builder.masterkeyFilename) //
		)));
	}

	CharSequence passphrase() {
		return (CharSequence) get(PROPERTY_PASSPHRASE);
	}

	@SuppressWarnings("unchecked")
	Set<FileSystemFlags> flags() {
		return (Set<FileSystemFlags>) get(PROPERTY_FILESYSTEM_FLAGS);
	}

	boolean readonly() {
		return flags().contains(FileSystemFlags.READONLY);
	}

	boolean initializeImplicitly() {
		return flags().contains(FileSystemFlags.INIT_IMPLICITLY);
	}

	String masterkeyFilename() {
		return (String) get(PROPERTY_MASTERKEY_FILENAME);
	}

	@Override
	public Set<Entry<String, Object>> entrySet() {
		return entries;
	}

	private static Entry<String, Object> entry(String key, Object value) {
		return new Entry<String, Object>() {
			@Override
			public String getKey() {
				return key;
			}

			@Override
			public Object getValue() {
				return value;
			}

			@Override
			public Object setValue(Object value) {
				throw new UnsupportedOperationException();
			}
		};
	}

	/**
	 * Starts construction of {@code CryptoFileSystemProperties}
	 * 
	 * @return a {@link Builder} which can be used to construct {@code CryptoFileSystemProperties}
	 */
	public static Builder cryptoFileSystemProperties() {
		return new Builder();
	}

	/**
	 * Starts construction of {@code CryptoFileSystemProperties}
	 * 
	 * @param properties a {@link Map} containing properties used to initialize the builder
	 * @return a {@link Builder} which can be used to construct {@code CryptoFileSystemProperties} and has been initialized with the values from properties
	 */
	public static Builder cryptoFileSystemPropertiesFrom(Map<String, ?> properties) {
		return new Builder(properties);
	}

	/**
	 * Constructs {@code CryptoFileSystemProperties} from a {@link Map}.
	 * 
	 * @param properties the {@code Map} to convert
	 * @return the passed in {@code Map} if already of type {@code CryptoFileSystemProperties} or a new {@code CryptoFileSystemProperties} instance holding the values from the {@code Map}
	 * @throws IllegalArgumentException if a value in the {@code Map} does not have the expected type or if a required value is missing
	 */
	public static CryptoFileSystemProperties wrap(Map<String, ?> properties) {
		if (properties instanceof CryptoFileSystemProperties) {
			return (CryptoFileSystemProperties) properties;
		} else {
			try {
				return cryptoFileSystemPropertiesFrom(properties).build();
			} catch (IllegalStateException e) {
				throw new IllegalArgumentException(e);
			}
		}
	}

	/**
	 * Builds {@link CryptoFileSystemProperties}
	 */
	public static class Builder {

		private CharSequence passphrase;
		private final Set<FileSystemFlags> flags = EnumSet.copyOf(DEFAULT_FILESYSTEM_FLAGS);
		private String masterkeyFilename = DEFAULT_MASTERKEY_FILENAME;

		private Builder() {
		}

		private Builder(Map<String, ?> properties) {
			checkedSet(CharSequence.class, PROPERTY_PASSPHRASE, properties, this::withPassphrase);
			checkedSet(String.class, PROPERTY_MASTERKEY_FILENAME, properties, this::withMasterkeyFilename);
			checkedSet(Set.class, PROPERTY_FILESYSTEM_FLAGS, properties, this::withFlags);
		}

		private <T> void checkedSet(Class<T> type, String key, Map<String, ?> properties, Consumer<T> setter) {
			Object value = properties.get(key);
			if (value == null) {
				return;
			} else if (type.isInstance(value)) {
				setter.accept(type.cast(value));
			} else {
				throw new IllegalArgumentException(key + " must be of type " + type.getSimpleName());
			}
		}

		/**
		 * Sets the passphrase to use for a CryptoFileSystem.
		 * 
		 * @param passphrase the passphrase to use
		 * @return this
		 */
		public Builder withPassphrase(CharSequence passphrase) {
			this.passphrase = passphrase;
			return this;
		}

		public Builder withFlags(FileSystemFlags... flags) {
			return withFlags(Arrays.asList(flags));
		}

		public Builder withFlags(Collection<FileSystemFlags> flags) {
			this.flags.clear();
			this.flags.addAll(flags);
			return this;
		}

		/**
		 * Sets the readonly flag for a CryptoFileSystem.
		 * 
		 * @return this
		 */
		public Builder withReadonlyFlag() {
			flags.add(FileSystemFlags.READONLY);
			return this;
		}

		/**
		 * Sets the name of the masterkey file located inside the vault directory.
		 * 
		 * @param masterkeyFilename the filename of the json file containing configuration to decrypt the masterkey
		 * @return this
		 * @since 1.1.0
		 */
		public Builder withMasterkeyFilename(String masterkeyFilename) {
			this.masterkeyFilename = masterkeyFilename;
			return this;
		}

		/**
		 * Validates the values and creates new {@link CryptoFileSystemProperties}.
		 * 
		 * @return a new {@code CryptoFileSystemProperties} with the values from this builder
		 * @throws IllegalStateException if a required value was not set on this {@code Builder}
		 */
		public CryptoFileSystemProperties build() {
			validate();
			return new CryptoFileSystemProperties(this);
		}

		private void validate() {
			if (passphrase == null) {
				throw new IllegalStateException("passphrase is required");
			}
			if (StringUtils.isBlank(masterkeyFilename)) {
				throw new IllegalStateException("masterkeyFilename is required");
			}
		}

	}

}
