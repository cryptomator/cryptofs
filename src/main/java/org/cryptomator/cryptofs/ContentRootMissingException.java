package org.cryptomator.cryptofs;

import java.nio.file.NoSuchFileException;

public class ContentRootMissingException extends NoSuchFileException {

	public ContentRootMissingException(String msg) {
		super(msg);
	}
}
