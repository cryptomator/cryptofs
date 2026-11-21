package org.cryptomator.cryptofs.fh;

import jakarta.inject.Inject;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The {@link BasicFileAttributes#fileKey() file key} of the ciphertext file an open file was opened on.
 * Used to recognize a ciphertext file that got replaced outside of this file system while the file is open.
 * <p>
 * File systems without file keys (e.g. on Windows) never capture one, so that every key {@link #matches(Object) matches}.
 */
@OpenFileScoped
public class CiphertextFileKey {

	private final AtomicReference<Object> capturedKey = new AtomicReference<>();

	@Inject
	public CiphertextFileKey() {
		// nothing to initialize, the key gets captured later
	}

	/**
	 * Reads the file key of the given ciphertext file.
	 *
	 * @param ciphertextPath Path of the ciphertext file
	 * @return The file key, or <code>null</code> if the file system has none
	 * @throws IOException If the attributes of the file cannot be read, e.g. because it doesn't exist
	 */
	public static Object read(Path ciphertextPath) throws IOException {
		return readAttributes(ciphertextPath).fileKey();
	}

	/**
	 * Reads the attributes of the given ciphertext file, to take its file key and other attributes from the same file.
	 *
	 * @param ciphertextPath Path of the ciphertext file
	 * @return The attributes of the file
	 * @throws IOException If the attributes of the file cannot be read, e.g. because it doesn't exist
	 */
	public static BasicFileAttributes readAttributes(Path ciphertextPath) throws IOException {
		return Files.readAttributes(ciphertextPath, BasicFileAttributes.class);
	}

	/**
	 * @param fileKey The file key of the ciphertext file this open file is using, or <code>null</code> if unknown
	 */
	public void capture(Object fileKey) {
		capturedKey.set(fileKey);
	}

	/**
	 * @return Whether a file key was captured
	 */
	public boolean isCaptured() {
		return capturedKey.get() != null;
	}

	/**
	 * @param fileKey A file key read from the ciphertext path, or <code>null</code> if unknown
	 * @return <code>false</code> only if both the captured key and the given key are known and differ
	 */
	public boolean matches(Object fileKey) {
		var captured = capturedKey.get();
		return captured == null || fileKey == null || Objects.equals(captured, fileKey);
	}

}
