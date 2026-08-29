package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class RegressionTest {

	/**
	 * For cryptofs to function properly {@link Files#readAttributes(Path, Class, LinkOption...)} must throw a
	 * {@link NoSuchFileException} if the targeted file does not exist.<br>
	 * This behavior is not guaranteed by the JDK specification, although the JDK itself depends on it.
	 * Internal discussions concluded that depending on this behavior and testing for any regressions is
	 * preferable to abiding strictly to the specification.
	 *
	 * @see CryptoPathMapper#getCiphertextFileType(CryptoPath)
	 */
	@Test
	public void testNotExistingFile(@TempDir Path dir) {
		assertThrows(NoSuchFileException.class, () -> Files.readAttributes(dir.resolve("notExistingFile"), BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS));
		assertThrows(NoSuchFileException.class, () -> Files.readAttributes(dir.resolve("notExistingFile"), BasicFileAttributes.class));
	}
}
