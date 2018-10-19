/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.OpenCryptoFileModule.openCryptoFileModule;
import static org.cryptomator.cryptofs.UncheckedThrows.allowUncheckedThrowsOf;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.inject.Inject;

@PerFileSystem
class OpenCryptoFiles {

	private final CryptoFileSystemComponent component;
	private final FinallyUtil finallyUtil;
	private final ConcurrentMap<Path, OpenCryptoFile> openCryptoFiles = new ConcurrentHashMap<>();


	@Inject
	public OpenCryptoFiles(CryptoFileSystemComponent component, FinallyUtil finallyUtil) {
		this.component = component;
		this.finallyUtil = finallyUtil;
	}

	public Optional<OpenCryptoFile> get(Path ciphertextPath) {
		return Optional.ofNullable(openCryptoFiles.get(ciphertextPath));
	}

	public OpenCryptoFile getOrCreate(Path ciphertextPath, EffectiveOpenOptions options) throws IOException {
		Path normalizedPath = ciphertextPath.toAbsolutePath().normalize();

		OpenCryptoFile result = allowUncheckedThrowsOf(IOException.class).from(() -> {
			return openCryptoFiles.computeIfAbsent(normalizedPath, ignored -> create(normalizedPath, options));
		});
		assert result != null : "computeIfAbsent will not return null";
		return result;
	}

	public void prepareMove(Path oldCiphertextPath, Path newCiphertextPath){
		openCryptoFiles.compute(newCiphertextPath, (key,fileAtNewCiphertextPath) -> {
			if(fileAtNewCiphertextPath == null){
				return openCryptoFiles.get(oldCiphertextPath);
			} else {
				throw new IllegalStateException("File already exists. Can't update map.");
			}

		});
	}

	public void commitMove(Path oldCiphertextPath){
		openCryptoFiles.remove(oldCiphertextPath);
	}

	public void rollbackMove(Path newCiphertextPath){
		openCryptoFiles.remove(newCiphertextPath);
	}

	public void close() throws IOException {
		finallyUtil.guaranteeInvocationOf( //
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
