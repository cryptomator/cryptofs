package org.cryptomator.cryptofs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

@PerOpenFile
class ExceptionsDuringWrite {

	private final List<IOException> exceptions = new ArrayList<>(); // todo handle / deliver exception

	@Inject
	public ExceptionsDuringWrite() {
	}

	public void add(IOException e) {
		exceptions.add(e);
	}

}
