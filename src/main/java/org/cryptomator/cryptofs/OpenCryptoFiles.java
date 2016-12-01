/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.FinallyUtils.guaranteeInvocationOf;
import static org.cryptomator.cryptofs.OpenCryptoFileModule.openCryptoFileModule;
import static org.cryptomator.cryptofs.UncheckedThrows.allowUncheckedThrowsOf;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.inject.Inject;

@PerFileSystem
class OpenCryptoFiles {

	private final CryptoFileSystemComponent component;
	private final ConcurrentMap<Path, OpenCryptoFile> openCryptoFiles = new ConcurrentHashMap<>();

	@Inject
	public OpenCryptoFiles(CryptoFileSystemComponent component) {
		this.component = component;
	}

	public OpenCryptoFile get(Path path, EffectiveOpenOptions options) throws IOException {
		Path normalizedPath = path.toAbsolutePath().normalize();

		OpenCryptoFile result = allowUncheckedThrowsOf(IOException.class).from(() -> {
			return openCryptoFiles.computeIfAbsent(normalizedPath, ignored -> create(normalizedPath, options));
		});
		assert result != null : "computeIfAbsent will not return null";
		return result;
	}

	public void close() throws IOException {
		guaranteeInvocationOf( //
				openCryptoFiles.values().stream() //
						.map(openCryptoFile -> (RunnableThrowingException<IOException>) () -> openCryptoFile.close()) //
						.iterator());
	}

	private OpenCryptoFile create(Path normalizedPath, EffectiveOpenOptions options) {
		return component
				.newOpenCryptoFileComponent(openCryptoFileModule() //
						.withPath(normalizedPath) //
						.withOptions(options) //
						.onClose(() -> openCryptoFiles.remove(normalizedPath)) //
						.build()) //
				.openCryptoFile();
	}

}
