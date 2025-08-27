package org.cryptomator.cryptofs.inuse;

import org.cryptomator.cryptofs.fh.FileAlreadyInUseException;
import org.cryptomator.cryptofs.fh.UseToken;

import java.io.IOException;
import java.nio.file.Path;

public interface InUseManager {

	boolean isInUse(Path ciphertextPath) throws IOException, IllegalArgumentException;

	UseToken use(Path ciphertextPath) throws FileAlreadyInUseException;

}
