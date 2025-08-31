package org.cryptomator.cryptofs.inuse;

import org.cryptomator.cryptofs.fh.FileAlreadyInUseException;

import java.io.IOException;
import java.nio.file.Path;

public class StubInUseManager implements InUseManager {

	@Override
	public boolean isInUseByOthers(Path ciphertextPath) {
		return false;
	}

	@Override
	public UseToken use(Path ciphertextPath) throws FileAlreadyInUseException {
		return UseToken.INIT_TOKEN;
	}
}
