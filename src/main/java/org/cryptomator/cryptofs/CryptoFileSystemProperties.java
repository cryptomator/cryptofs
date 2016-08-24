/*******************************************************************************
 * Copyright (c) 2016 Markus Kreusch and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Markus Kreusch - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.lang.Boolean.TRUE;
import static java.util.Arrays.asList;

import java.net.URI;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.AbstractMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Properties to pass to
 * <ul>
 *   <li>{@link FileSystems#newFileSystem(URI, Map)} or
 *   <li>{@link CryptoFileSystemProvider#newFileSystem(Path, CryptoFileSystemProperties)}.
 * </ul>
 * 
 * @author Markus Kreusch
 */
public final class CryptoFileSystemProperties extends AbstractMap<String, Object> {

	/**
	 * Key identifying the passphrase for a encrypted vault.
	 */
	public static final String PROPERTY_PASSPHRASE = "passphrase";

	/**
	 * Key identifying the readonly property (<code>true</code> or <code>false</code>) for a vault.
	 */
	public static final String PROPERTY_READONLY = "readonly";

	private final Set<Entry<String, Object>> entries;

	private CryptoFileSystemProperties(Builder builder) {
		this.entries = new HashSet<>(asList( //
				entry(PROPERTY_PASSPHRASE, builder.passphrase), //
				entry(PROPERTY_READONLY, builder.readonly)));
	}

	CharSequence passphrase() {
		return (CharSequence) get(PROPERTY_PASSPHRASE);
	}

	boolean readonly() {
		return (boolean) get(PROPERTY_READONLY);
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
			return (CryptoFileSystemProperties)properties;
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
		private boolean readonly = false;

		private Builder() {
		}

		private Builder(Map<String, ?> properties) {
			checkedSet(CharSequence.class, PROPERTY_PASSPHRASE, properties, this::withPassphrase);
			checkedSet(Boolean.class, PROPERTY_READONLY, properties, readonly -> {
				if (TRUE.equals(readonly)) {
					withReadonlyFlag();
				}
			});
			
		}

		private <T> void checkedSet(Class<T> type, String key, Map<String,?> properties, Consumer<T> setter) {
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

		/**
		 * Sets the readonly flag for a CryptoFileSystem.
		 * 
		 * @return this
		 */
		public Builder withReadonlyFlag() {
			this.readonly = true;
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
		}

	}

}
