package org.cryptomator.cryptofs.fh;

import java.nio.file.Path;

@FunctionalInterface
public interface FileCloseListener {

	/**
	 * @see java.util.Map#remove(Object, Object)
	 */
	boolean close(Path path, OpenCryptoFile file);

}
