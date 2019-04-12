/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.nio.file.StandardOpenOption.APPEND;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.DELETE_ON_CLOSE;
import static java.nio.file.StandardOpenOption.DSYNC;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.SPARSE;
import static java.nio.file.StandardOpenOption.SYNC;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;

import java.io.IOException;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.Set;

public class EffectiveOpenOptions {

	private final ReadonlyFlag readonlyFlag;
	private final Set<OpenOption> options;

	private EffectiveOpenOptions(Set<? extends OpenOption> options, ReadonlyFlag readonlyFlag) throws IOException {
		this.readonlyFlag = readonlyFlag;
		this.options = cleanAndValidate(options);
	}

	public static EffectiveOpenOptions from(Set<? extends OpenOption> options, ReadonlyFlag readonlyFlag) throws IOException {
		return new EffectiveOpenOptions(options, readonlyFlag);
	}

	/**
	 * @see LinkOption#NOFOLLOW_LINKS
	 */
	public boolean noFollowLinks() {
		return options.contains(LinkOption.NOFOLLOW_LINKS);
	}

	/**
	 * @see StandardOpenOption#WRITE
	 */
	public boolean writable() {
		return options.contains(WRITE);
	}

	/**
	 * @see StandardOpenOption#READ
	 */
	public boolean readable() {
		return options.contains(READ);
	}

	/**
	 * @see StandardOpenOption#SYNC
	 */
	public boolean syncDataAndMetadata() {
		return options.contains(SYNC);
	}

	/**
	 * @see StandardOpenOption#DSYNC
	 */
	public boolean syncData() {
		return syncDataAndMetadata() || options.contains(DSYNC);
	}

	/**
	 * @see StandardOpenOption#APPEND
	 */
	public boolean append() {
		return options.contains(APPEND);
	}

	/**
	 * @see StandardOpenOption#CREATE_NEW
	 */
	public boolean createNew() {
		return options.contains(CREATE_NEW);
	}

	/**
	 * @see StandardOpenOption#CREATE
	 */
	public boolean create() {
		return options.contains(CREATE);
	}

	/**
	 * @see StandardOpenOption#TRUNCATE_EXISTING
	 */
	public boolean truncateExisting() {
		return options.contains(TRUNCATE_EXISTING);
	}

	/**
	 * @see StandardOpenOption#DELETE_ON_CLOSE
	 */
	public boolean deleteOnClose() {
		return options.contains(DELETE_ON_CLOSE);
	}

	private Set<OpenOption> cleanAndValidate(Set<? extends OpenOption> originalOptions) throws IOException {
		Set<OpenOption> cleanedOptions = new HashSet<>(originalOptions);
		addWriteIfAppendIsPresent(cleanedOptions);
		addReadIfWriteIsAbsent(cleanedOptions);
		validateAppendIsNotPresentInConjuntionWithTruncateExistingOrRead(originalOptions);
		removeSparse(cleanedOptions);
		removeCreateIfCreateNewIsPresent(cleanedOptions);
		removeCreateAndTruncateOptionsIfWriteIsAbsent(cleanedOptions);
		validateNoUnsupportedOptionsArePresent(cleanedOptions);
		assertWritableIfWriteOrDeleteOnCloseIsPresent(cleanedOptions);
		return cleanedOptions;
	}

	private void addWriteIfAppendIsPresent(Set<OpenOption> options) {
		if (options.contains(APPEND)) {
			options.add(WRITE);
		}
	}

	private void addReadIfWriteIsAbsent(Set<OpenOption> options) {
		if (!options.contains(WRITE)) {
			options.add(READ);
		}
	}

	private void validateAppendIsNotPresentInConjuntionWithTruncateExistingOrRead(Set<? extends OpenOption> options) {
		if (options.contains(APPEND) && (options.contains(READ) || options.contains(TRUNCATE_EXISTING))) {
			throw new IllegalArgumentException("StandardOpenOption APPEND may not be used in conjuction with READ or TRUNCATE_EXISTING");
		}
	}

	private void removeSparse(Set<OpenOption> options) {
		options.remove(SPARSE);
	}

	private void removeCreateAndTruncateOptionsIfWriteIsAbsent(Set<OpenOption> options) {
		if (!options.contains(WRITE)) {
			options.remove(TRUNCATE_EXISTING);
			options.remove(CREATE_NEW);
			options.remove(CREATE);
		}
	}

	private void removeCreateIfCreateNewIsPresent(Set<OpenOption> options) {
		if (options.contains(CREATE_NEW)) {
			options.remove(CREATE);
		}
	}

	private void validateNoUnsupportedOptionsArePresent(Set<OpenOption> options) {
		for (OpenOption option : options) {
			if (!isSupported(option)) {
				throw new IllegalArgumentException("Unsupported option option " + option);
			}
		}
	}

	private void assertWritableIfWriteOrDeleteOnCloseIsPresent(Set<OpenOption> cleanedOptions) throws IOException {
		if (cleanedOptions.contains(WRITE) || cleanedOptions.contains(DELETE_ON_CLOSE)) {
			readonlyFlag.assertWritable();
		}
	}

	private boolean isSupported(OpenOption option) {
		return StandardOpenOption.class.isInstance(option) || LinkOption.class.isInstance(option);
	}

	public Set<OpenOption> createOpenOptionsForEncryptedFile() {
		Set<OpenOption> result = new HashSet<>(options);
		result.add(READ); // also needed during write
		result.remove(LinkOption.NOFOLLOW_LINKS);
		result.remove(APPEND);
		return result;
	}

}
