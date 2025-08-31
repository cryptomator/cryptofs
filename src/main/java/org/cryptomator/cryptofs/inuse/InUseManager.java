package org.cryptomator.cryptofs.inuse;

import org.cryptomator.cryptofs.fh.FileAlreadyInUseException;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Factory for
 */
public interface InUseManager {

	boolean isInUseByOthers(Path ciphertextPath) throws IOException, IllegalArgumentException;

	UseToken use(Path ciphertextPath) throws FileAlreadyInUseException;

}
