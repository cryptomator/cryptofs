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
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.MasterkeyLoader;

import java.net.URI;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.AbstractMap;
import java.util.Collection;
import java.util.EnumSet;
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
	 * Maximum cleartext filename length.
	 *
	 * @since 2.0.0
	 */
	public static final String PROPERTY_MAX_CLEARTEXT_NAME_LENGTH = "maxCleartextNameLength";

	static final int DEFAULT_MAX_CLEARTEXT_NAME_LENGTH = LongFileNameProvider.MAX_FILENAME_BUFFER_SIZE;

	/**
	 * Shortening threshold for ciphertext filenames.
	 *
	 * @since 2.5.0
	 */
	public static final String PROPERTY_SHORTENING_THRESHOLD = "shorteningThreshold";

	static final int DEFAULT_SHORTENING_THRESHOLD = 220;

	/**
	 * Key identifying the key loader used during initialization.
	 *
	 * @since 2.0.0
	 */
	public static final String PROPERTY_KEYLOADER = "keyLoader";

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
	 * @deprecated Replaced with {@link #PROPERTY_KEYLOADER external keyloader} API
	 */
	@Deprecated
	public static final String PROPERTY_MASTERKEY_FILENAME = "masterkeyFilename";

	static final String DEFAULT_MASTERKEY_FILENAME = "masterkey.cryptomator";

	/**
	 * Key identifying the function to call for notifications.
	 *
	 * @since 2.9.0
	 */
	public static final String PROPERTY_NOTIFY_METHOD = "notificationConsumer";

	static final Consumer<FilesystemEvent> DEFAULT_NOTIFY_METHOD = (FilesystemEvent e) -> {};

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

	static final CryptorProvider.Scheme DEFAULT_CIPHER_COMBO = CryptorProvider.Scheme.SIV_GCM;

	private final Set<Entry<String, Object>> entries;

	private CryptoFileSystemProperties(Builder builder) {
		this.entries = Set.of( //
				Map.entry(PROPERTY_KEYLOADER, builder.keyLoader), //
				Map.entry(PROPERTY_FILESYSTEM_FLAGS, builder.flags), //
				Map.entry(PROPERTY_VAULTCONFIG_FILENAME, builder.vaultConfigFilename), //
				Map.entry(PROPERTY_MASTERKEY_FILENAME, builder.masterkeyFilename), //
				Map.entry(PROPERTY_NOTIFY_METHOD, builder.eventConsumer), //
				Map.entry(PROPERTY_MAX_CLEARTEXT_NAME_LENGTH, builder.maxCleartextNameLength), //
				Map.entry(PROPERTY_SHORTENING_THRESHOLD, builder.shorteningThreshold), //
				Map.entry(PROPERTY_CIPHER_COMBO, builder.cipherCombo) //
		);
	}

	MasterkeyLoader keyLoader() {
		return (MasterkeyLoader) get(PROPERTY_KEYLOADER);
	}

	public CryptorProvider.Scheme cipherCombo() {
		return (CryptorProvider.Scheme) get(PROPERTY_CIPHER_COMBO);
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

	@Deprecated
	String masterkeyFilename() {
		return (String) get(PROPERTY_MASTERKEY_FILENAME);
	}

	int maxCleartextNameLength() {
		return (int) get(PROPERTY_MAX_CLEARTEXT_NAME_LENGTH);
	}

	int shorteningThreshold() {
		return (int) get(PROPERTY_SHORTENING_THRESHOLD);
	}

	Consumer<FilesystemEvent> fsEventConsumner() {
		return (Consumer<FilesystemEvent>) get(PROPERTY_NOTIFY_METHOD);
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
		if (properties instanceof CryptoFileSystemProperties p) {
			return p;
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

		public CryptorProvider.Scheme cipherCombo = DEFAULT_CIPHER_COMBO;
		private MasterkeyLoader keyLoader = null;
		private final Set<FileSystemFlags> flags = EnumSet.copyOf(DEFAULT_FILESYSTEM_FLAGS);
		private String vaultConfigFilename = DEFAULT_VAULTCONFIG_FILENAME;
		private String masterkeyFilename = DEFAULT_MASTERKEY_FILENAME;
		private int maxCleartextNameLength = DEFAULT_MAX_CLEARTEXT_NAME_LENGTH;
		private int shorteningThreshold = DEFAULT_SHORTENING_THRESHOLD;
		private Consumer<FilesystemEvent> eventConsumer = DEFAULT_NOTIFY_METHOD;

		private Builder() {
		}

		private Builder(Map<String, ?> properties) {
			checkedSet(MasterkeyLoader.class, PROPERTY_KEYLOADER, properties, this::withKeyLoader);
			checkedSet(String.class, PROPERTY_VAULTCONFIG_FILENAME, properties, this::withVaultConfigFilename);
			checkedSet(String.class, PROPERTY_MASTERKEY_FILENAME, properties, this::withMasterkeyFilename);
			checkedSet(Set.class, PROPERTY_FILESYSTEM_FLAGS, properties, this::withFlags);
			checkedSet(Integer.class, PROPERTY_MAX_CLEARTEXT_NAME_LENGTH, properties, this::withMaxCleartextNameLength);
			checkedSet(Integer.class, PROPERTY_SHORTENING_THRESHOLD, properties, this::withShorteningThreshold);
			checkedSet(CryptorProvider.Scheme.class, PROPERTY_CIPHER_COMBO, properties, this::withCipherCombo);
			checkedSet(Consumer.class, PROPERTY_NOTIFY_METHOD, properties, this::withFilesystemEventConsumer);
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
		 * Sets the maximum cleartext filename length for a CryptoFileSystem. This value is checked during write
		 * operations. Read access to nodes with longer names should be unaffected. Setting this value to {@code 0} or
		 * a negative value effectively disables write access.
		 *
		 * @param maxCleartextNameLength The maximum cleartext filename length allowed
		 * @return this
		 * @since 2.0.0
		 */
		public Builder withMaxCleartextNameLength(int maxCleartextNameLength) {
			this.maxCleartextNameLength = maxCleartextNameLength;
			return this;
		}

		/**
		 * Sets the shortening threshold used during vault initialization.
		 *
		 * @param shorteningThreshold The maximum ciphertext filename length not to be shortened
		 * @return this
		 * @since 2.5.0
		 */
		public Builder withShorteningThreshold(int shorteningThreshold) {
			this.shorteningThreshold = shorteningThreshold;
			return this;
		}


		/**
		 * Sets the cipher combo used during vault initialization.
		 *
		 * @param cipherCombo The cipher combo
		 * @return this
		 * @since 2.0.0
		 */
		public Builder withCipherCombo(CryptorProvider.Scheme cipherCombo) {
			this.cipherCombo = cipherCombo;
			return this;
		}

		/**
		 * Sets the keyloader for a CryptoFileSystem.
		 *
		 * @param keyLoader A factory creating a {@link MasterkeyLoader} capable of handling the given {@code scheme}.
		 * @return this
		 * @since 2.0.0
		 */
		public Builder withKeyLoader(MasterkeyLoader keyLoader) {
			this.keyLoader = keyLoader;
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
		 * @deprecated Supply a {@link #withKeyLoader(MasterkeyLoader) keyloader} instead.
		 */
		@Deprecated
		public Builder withMasterkeyFilename(String masterkeyFilename) {
			this.masterkeyFilename = masterkeyFilename;
			return this;
		}

		/**
		 * Sets the consumer for filesystem events
		 *
		 * @param eventConsumer the consumer to receive filesystem events
		 * @return this
		 * @since 2.8.0
		 */
		public Builder withFilesystemEventConsumer(Consumer<FilesystemEvent> eventConsumer) {
			if (eventConsumer == null) {
				throw new IllegalArgumentException("Parameter eventConsumer must not be null");
			}
			this.eventConsumer = eventConsumer;
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
			if (keyLoader == null) {
				throw new IllegalStateException("keyLoader is required");
			}
			if (Strings.nullToEmpty(masterkeyFilename).trim().isEmpty()) {
				throw new IllegalStateException("masterkeyFilename is required");
			}
		}

	}

}
