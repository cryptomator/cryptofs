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

import java.nio.file.OpenOption;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.Set;

class EffectiveOpenOptions {

	public static EffectiveOpenOptions from(Set<? extends OpenOption> options) {
		return new EffectiveOpenOptions(options);
	}

	private final Set<OpenOption> options;

	private EffectiveOpenOptions(Set<? extends OpenOption> options) {
		this.options = cleanAndValidate(options);
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

	private Set<OpenOption> cleanAndValidate(Set<? extends OpenOption> originalOptions) {
		Set<OpenOption> cleanedOptions = new HashSet<>(originalOptions);
		addWriteIfAppendIsPresent(cleanedOptions);
		addReadIfWriteIsAbsent(cleanedOptions);
		validateAppendIsNotPresentInConjuntionWithTruncateExistingOrRead(originalOptions);
		removeSparse(cleanedOptions);
		removeCreateIfCreateNewIsPresent(cleanedOptions);
		removeCreateAndTruncateOptionsIfWriteIsAbsent(cleanedOptions);
		validateNoUnsupportedOptionsArePresent(cleanedOptions);
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

	private boolean isSupported(OpenOption option) {
		return StandardOpenOption.class.isInstance(option);
	}

	public Set<OpenOption> createOpenOptionsForEncryptedFile() {
		Set<OpenOption> result = new HashSet<>(options);
		result.removeIf(option -> !StandardOpenOption.class.isInstance(option));
		result.add(READ); // also needed during write
		result.remove(APPEND);
		return result;
	}

	/**
	 * @return Same as {@link #createOpenOptionsForEncryptedFile()} but with StandardOpenOption#CREATE_NEW, i.e. assert file does not exist!
	 */
	public Set<OpenOption> createOpenOptionsForNonExistingEncryptedFile() {
		Set<OpenOption> result = createOpenOptionsForEncryptedFile();
		result.add(CREATE_NEW);
		return result;
	}

}
