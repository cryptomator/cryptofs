/*******************************************************************************
 * Copyright (c) 2016 Markus Kreusch and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Markus Kreusch - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import com.google.common.base.Strings;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;

import java.net.URI;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.AbstractMap;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import static java.util.Arrays.asList;

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
	 * Maximum ciphertext path length.
	 *
	 * @since 1.9.8
	 */
	public static final String PROPERTY_MAX_PATH_LENGTH = "maxPathLength";

	static final int DEFAULT_MAX_PATH_LENGTH = Constants.MAX_CIPHERTEXT_PATH_LENGTH;

	/**
	 * Maximum filename length of .c9r files.
	 *
	 * @since 1.9.9
	 */
	public static final String PROPERTY_MAX_NAME_LENGTH = "maxNameLength";

	static final int DEFAULT_MAX_NAME_LENGTH = Constants.MAX_CIPHERTEXT_NAME_LENGTH;

	/**
	 * Key identifying the key loader used during initialization.
	 *
	 * @since 2.0.0
	 */
	public static final String PROPERTY_KEYLOADERS = "keyLoaders";

	static final Collection<MasterkeyLoader> DEFAULT_KEYLOADERS = Set.of();

	/**
	 * Key identifying the name of the vault config file located inside the vault directory.
	 *
	 * @since 2.0.0
	 */
	public static final String PROPERTY_VAULTCONFIG_FILENAME = "vaultConfigFilename";

	static final String DEFAULT_VAULTCONFIG_FILENAME = "vault.cryptomator";

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

	static final Set<FileSystemFlags> DEFAULT_FILESYSTEM_FLAGS = EnumSet.noneOf(FileSystemFlags.class);

	public enum FileSystemFlags {
		/**
		 * If present, the vault is opened in read-only mode.
		 */
		READONLY,
	}

	/**
	 * Key identifying the combination of ciphers to use in a vault. Only meaningful during vault initialization.
	 *
	 * @since 2.0.0
	 */
	public static final String PROPERTY_CIPHER_COMBO = "cipherCombo";

	static final VaultCipherCombo DEFAULT_CIPHER_COMBO = VaultCipherCombo.SIV_GCM;

	private final Set<Entry<String, Object>> entries;

	private CryptoFileSystemProperties(Builder builder) {
		this.entries = Set.of( //
				Map.entry(PROPERTY_KEYLOADERS, builder.keyLoaders), //
				Map.entry(PROPERTY_FILESYSTEM_FLAGS, builder.flags), //
				Map.entry(PROPERTY_VAULTCONFIG_FILENAME, builder.vaultConfigFilename), //
				Map.entry(PROPERTY_MASTERKEY_FILENAME, builder.masterkeyFilename), //
				Map.entry(PROPERTY_MAX_PATH_LENGTH, builder.maxPathLength), //
				Map.entry(PROPERTY_MAX_NAME_LENGTH, builder.maxNameLength), //
				Map.entry(PROPERTY_CIPHER_COMBO, builder.cipherCombo) //
		);
	}

	Collection<MasterkeyLoader> keyLoaders() {
		return (Collection<MasterkeyLoader>) get(PROPERTY_KEYLOADERS);
	}

	/**
	 * Selects the first applicable MasterkeyLoader that supports the given scheme.
	 *
	 * @param scheme An URI scheme used in key IDs
	 * @return A key loader
	 * @throws MasterkeyLoadingFailedException If the scheme is not supported by any key loader
	 */
	MasterkeyLoader keyLoader(String scheme) throws MasterkeyLoadingFailedException {
		for (MasterkeyLoader loader : keyLoaders()) {
			if (loader.supportsScheme(scheme)) {
				return loader;
			}
		}
		throw new MasterkeyLoadingFailedException("No key loader for key type: " + scheme);
	}

	public VaultCipherCombo cipherCombo() {
		return (VaultCipherCombo) get(PROPERTY_CIPHER_COMBO);
	}

	@SuppressWarnings("unchecked")
	public Set<FileSystemFlags> flags() {
		return (Set<FileSystemFlags>) get(PROPERTY_FILESYSTEM_FLAGS);
	}

	public boolean readonly() {
		return flags().contains(FileSystemFlags.READONLY);
	}

	String vaultConfigFilename() {
		return (String) get(PROPERTY_VAULTCONFIG_FILENAME);
	}

	String masterkeyFilename() {
		return (String) get(PROPERTY_MASTERKEY_FILENAME);
	}

	int maxPathLength() {
		return (int) get(PROPERTY_MAX_PATH_LENGTH);
	}

	int maxNameLength() {
		return (int) get(PROPERTY_MAX_NAME_LENGTH);
	}

	@Override
	public Set<Entry<String, Object>> entrySet() {
		return entries;
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

		public VaultCipherCombo cipherCombo = DEFAULT_CIPHER_COMBO;
		private Collection<MasterkeyLoader> keyLoaders = new HashSet<>(DEFAULT_KEYLOADERS);
		private final Set<FileSystemFlags> flags = EnumSet.copyOf(DEFAULT_FILESYSTEM_FLAGS);
		private String vaultConfigFilename = DEFAULT_VAULTCONFIG_FILENAME;
		private String masterkeyFilename = DEFAULT_MASTERKEY_FILENAME;
		private int maxPathLength = DEFAULT_MAX_PATH_LENGTH;
		private int maxNameLength = DEFAULT_MAX_NAME_LENGTH;

		private Builder() {
		}

		private Builder(Map<String, ?> properties) {
			checkedSet(Collection.class, PROPERTY_KEYLOADERS, properties, this::withKeyLoaders);
			checkedSet(String.class, PROPERTY_VAULTCONFIG_FILENAME, properties, this::withVaultConfigFilename);
			checkedSet(String.class, PROPERTY_MASTERKEY_FILENAME, properties, this::withMasterkeyFilename);
			checkedSet(Set.class, PROPERTY_FILESYSTEM_FLAGS, properties, this::withFlags);
			checkedSet(Integer.class, PROPERTY_MAX_PATH_LENGTH, properties, this::withMaxPathLength);
			checkedSet(Integer.class, PROPERTY_MAX_NAME_LENGTH, properties, this::withMaxNameLength);
			checkedSet(VaultCipherCombo.class, PROPERTY_CIPHER_COMBO, properties, this::withCipherCombo);
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
		 * Sets the maximum ciphertext path length for a CryptoFileSystem.
		 *
		 * @param maxPathLength The maximum ciphertext path length allowed
		 * @return this
		 * @since 1.9.8
		 */
		public Builder withMaxPathLength(int maxPathLength) {
			this.maxPathLength = maxPathLength;
			return this;
		}

		/**
		 * Sets the maximum ciphertext filename length for a CryptoFileSystem.
		 *
		 * @param maxNameLength The maximum ciphertext filename length allowed
		 * @return this
		 * @since 1.9.9
		 */
		public Builder withMaxNameLength(int maxNameLength) {
			this.maxNameLength = maxNameLength;
			return this;
		}


		/**
		 * Sets the cipher combo used during vault initialization.
		 *
		 * @param cipherCombo The cipher combo
		 * @return this
		 * @since 2.0.0
		 */
		public Builder withCipherCombo(VaultCipherCombo cipherCombo) {
			this.cipherCombo = cipherCombo;
			return this;
		}

		/**
		 * Sets the keyLoaders for a CryptoFileSystem.
		 *
		 * @param keyLoaders A set of keyLoaders to load the key configured in the vault configuration
		 * @return this
		 * @since 2.0.0
		 */
		public Builder withKeyLoaders(MasterkeyLoader... keyLoaders) {
			return withKeyLoaders(asList(keyLoaders));
		}

		/**
		 * Sets the keyLoaders for a CryptoFileSystem.
		 *
		 * @param keyLoaders A set of keyLoaders to load the key configured in the vault configuration
		 * @return this
		 * @since 2.0.0
		 */
		public Builder withKeyLoaders(Collection<MasterkeyLoader> keyLoaders) {
			this.keyLoaders.clear();
			this.keyLoaders.addAll(keyLoaders);
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
			this.flags.clear();
			this.flags.addAll(flags);
			return this;
		}

		/**
		 * Sets the name of the vault config file located inside the vault directory.
		 *
		 * @param vaultConfigFilename the filename of the jwt file containing the vault configuration
		 * @return this
		 * @since 2.0.0
		 */
		public Builder withVaultConfigFilename(String vaultConfigFilename) {
			this.vaultConfigFilename = vaultConfigFilename;
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
			if (keyLoaders.isEmpty()) {
				throw new IllegalStateException("at least one keyloader is required");
			}
			if (Strings.nullToEmpty(masterkeyFilename).trim().isEmpty()) {
				throw new IllegalStateException("masterkeyFilename is required");
			}
		}

	}

}
