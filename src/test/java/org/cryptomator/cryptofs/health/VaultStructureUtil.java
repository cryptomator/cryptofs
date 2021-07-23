package org.cryptomator.cryptofs.health;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class VaultStructureUtil {

	/**
	 * TODO: doc doc doc
	 *
	 * @param root
	 * @param structure
	 * @throws UncheckedIOException
	 */
	public static void initDirStructure(Path root, String structure) throws UncheckedIOException {
		structure.lines().forEach(line -> {
			try {
				if (line.contains(" = ")) {
					var sep = line.indexOf(" = ");
					var file = root.resolve(line.substring(0, sep));
					var contents = line.substring(sep + 3);
					Files.createDirectories(file.getParent());
					if (contents.equals("[EMPTY]")) {
						Files.createFile(file);
					} else {
						Files.writeString(file, contents, StandardCharsets.US_ASCII, StandardOpenOption.CREATE_NEW);

					}
				} else {
					Files.createDirectories(root.resolve(line));
				}
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		});
	}
}
