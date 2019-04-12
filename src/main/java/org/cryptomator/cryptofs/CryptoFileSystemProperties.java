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
import java.text.Normalizer;
import java.text.Normalizer.Form;
import java.util.AbstractMap;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import com.google.common.base.Strings;

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
	 * Key identifying the pepper used during key derivation.
	 * 
	 * @since 1.3.2
	 */
	public static final String PROPERTY_PEPPER = "pepper";

	static final byte[] DEFAULT_PEPPER = new byte[0];

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

	static final Set<FileSystemFlags> DEFAULT_FILESYSTEM_FLAGS = unmodifiableSet(EnumSet.of(FileSystemFlags.MIGRATE_IMPLICITLY, FileSystemFlags.INIT_IMPLICITLY));

	public enum FileSystemFlags {
		/**
		 * If present, the vault is opened in read-only mode.
		 * <p>
		 * This flag can not be set together with {@link #INIT_IMPLICITLY} or {@link #MIGRATE_IMPLICITLY}.
		 */
		READONLY,

		/**
		 * If present, the vault gets automatically migrated during file system creation, which might become significantly slower.
		 * If absent, a {@link FileSystemNeedsMigrationException} will get thrown during the attempt to open a vault that needs migration.
		 * <p>
		 * This flag can not be set together with {@link #READONLY}.
		 * 
		 * @since 1.4.0
		 */
		MIGRATE_IMPLICITLY,

		/**
		 * If present, the vault structure will implicitly get initialized upon filesystem creation.
		 * <p>
		 * This flag can not be set together with {@link #READONLY}.
		 * 
		 * @deprecated Will get removed in version 2.0.0. Use {@link CryptoFileSystemProvider#initialize(Path, String, CharSequence)} explicitly.
		 */
		@Deprecated INIT_IMPLICITLY
	};

	private final Set<Entry<String, Object>> entries;

	private CryptoFileSystemProperties(Builder builder) {
		this.entries = unmodifiableSet(new HashSet<>(asList( //
				entry(PROPERTY_PASSPHRASE, builder.passphrase), //
				entry(PROPERTY_PEPPER, builder.pepper), //
				entry(PROPERTY_FILESYSTEM_FLAGS, builder.flags), //
				entry(PROPERTY_MASTERKEY_FILENAME, builder.masterkeyFilename) //
		)));
	}

	CharSequence passphrase() {
		return (CharSequence) get(PROPERTY_PASSPHRASE);
	}

	byte[] pepper() {
		return (byte[]) get(PROPERTY_PEPPER);
	}

	@SuppressWarnings("unchecked")
	public Set<FileSystemFlags> flags() {
		return (Set<FileSystemFlags>) get(PROPERTY_FILESYSTEM_FLAGS);
	}

	public boolean readonly() {
		return flags().contains(FileSystemFlags.READONLY);
	}

	boolean migrateImplicitly() {
		return flags().contains(FileSystemFlags.MIGRATE_IMPLICITLY);
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
	 * Starts construction of {@code CryptoFileSystemProperties}.
	 * Convenience function for <code>cryptoFileSystemProperties().withPassphrase(passphrase)</code>.
	 * 
	 * @param passphrase the passphrase to use
	 * @return a {@link Builder} which can be used to construct {@code CryptoFileSystemProperties}
	 * @since 1.4.0
	 */
	public static Builder withPassphrase(CharSequence passphrase) {
		return new Builder().withPassphrase(passphrase);
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
		public byte[] pepper = DEFAULT_PEPPER;
		private final Set<FileSystemFlags> flags = EnumSet.copyOf(DEFAULT_FILESYSTEM_FLAGS);
		private String masterkeyFilename = DEFAULT_MASTERKEY_FILENAME;

		private Builder() {
		}

		private Builder(Map<String, ?> properties) {
			checkedSet(CharSequence.class, PROPERTY_PASSPHRASE, properties, this::withPassphrase);
			checkedSet(byte[].class, PROPERTY_PEPPER, properties, this::withPepper);
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
			this.passphrase = Normalizer.normalize(passphrase, Form.NFC);
			return this;
		}

		/**
		 * Sets the pepper for a CryptoFileSystem.
		 * 
		 * @param pepper A pepper used during key derivation
		 * @return this
		 * @since 1.3.2
		 */
		public Builder withPepper(byte[] pepper) {
			this.pepper = pepper;
			return this;
		}

		/**
		 * Sets the flags for a CryptoFileSystem.
		 * 
		 * @param flags File system flags
		 * @return this
		 * @since 1.3.1
		 */
		public Builder withFlags(FileSystemFlags... flags) {
			return withFlags(asList(flags));
		}

		/**
		 * Sets the flags for a CryptoFileSystem.
		 * 
		 * @param flags collection of file system flags
		 * @return this
		 * @since 1.3.0
		 */
		public Builder withFlags(Collection<FileSystemFlags> flags) {
			validate(flags);
			this.flags.clear();
			this.flags.addAll(flags);
			return this;
		}

		private void validate(Collection<FileSystemFlags> flags) {
			if (flags.contains(FileSystemFlags.READONLY)) {
				if (flags.contains(FileSystemFlags.INIT_IMPLICITLY)) {
					throw new IllegalStateException("Can not set flag INIT_IMPLICITLY in conjunction with flag READONLY.");
				}
				if (flags.contains(FileSystemFlags.MIGRATE_IMPLICITLY)) {
					throw new IllegalStateException("Can not set flag MIGRATE_IMPLICITLY in conjunction with flag READONLY.");
				}
			}
		}

		/**
		 * Sets the readonly flag for a CryptoFileSystem.
		 * 
		 * @return this
		 * @deprecated Will be removed in 2.0.0. Use {@link #withFlags(FileSystemFlags...) withFlags(FileSystemFlags.READONLY)}
		 */
		@Deprecated
		public Builder withReadonlyFlag() {
			flags.add(FileSystemFlags.READONLY);
			flags.remove(FileSystemFlags.INIT_IMPLICITLY);
			flags.remove(FileSystemFlags.MIGRATE_IMPLICITLY);
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
			if (Strings.nullToEmpty(masterkeyFilename).trim().isEmpty()) {
				throw new IllegalStateException("masterkeyFilename is required");
			}
		}

	}

}
