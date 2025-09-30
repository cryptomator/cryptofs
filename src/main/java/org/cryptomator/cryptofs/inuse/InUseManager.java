package org.cryptomator.cryptofs.inuse;


import java.io.IOException;
import java.nio.file.Path;

/**
 * Factory for
 */
public interface InUseManager {

	boolean isInUseByOthers(Path ciphertextPath);

	UseToken use(Path ciphertextPath) throws FileAlreadyInUseException;

}
