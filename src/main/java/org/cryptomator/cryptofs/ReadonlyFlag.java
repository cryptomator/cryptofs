package org.cryptomator.cryptofs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.ReadOnlyFileSystemException;

@CryptoFileSystemScoped
public class ReadonlyFlag {

	private static final Logger LOG = LoggerFactory.getLogger(ReadonlyFlag.class);

	private final boolean readonly;

	@Inject
	public ReadonlyFlag(CryptoFileSystemProperties properties) {
		if (properties.readonly()) {
			LOG.info("Vault opened readonly.");
			readonly = true;
		} else {
			LOG.debug("Vault opened for read and write.");
			readonly = false;
		}
	}

	public void assertWritable() throws ReadOnlyFileSystemException {
		if (readonly) {
			throw new ReadOnlyFileSystemException();
		}
	}

	public boolean isSet() {
		return readonly;
	}

}
