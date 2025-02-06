/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs;

import dagger.Module;
import dagger.Provides;
import org.cryptomator.cryptofs.attr.AttributeComponent;
import org.cryptomator.cryptofs.attr.AttributeViewComponent;
import org.cryptomator.cryptofs.dir.DirectoryStreamComponent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.cryptomator.cryptofs.fh.OpenCryptoFileComponent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.function.Consumer;

@Module(subcomponents = {AttributeComponent.class, AttributeViewComponent.class, OpenCryptoFileComponent.class, DirectoryStreamComponent.class})
class CryptoFileSystemModule {

	private static final Logger LOG = LoggerFactory.getLogger(CryptoFileSystemModule.class);

	@Provides
	@CryptoFileSystemScoped
	public Optional<FileStore> provideNativeFileStore(@PathToVault Path pathToVault) {
		try {
			return Optional.of(Files.getFileStore(pathToVault));
		} catch (IOException e) {
			LOG.warn("Failed to get file store for " + pathToVault, e);
			return Optional.empty();
		}
	}

	@Provides
	@CryptoFileSystemScoped
	public Consumer<FilesystemEvent> provideFilesystemEventConsumer(CryptoFileSystemProperties fsProps) {
		var eventConsumer = fsProps.fsEventConsumner();
		return event -> {
			try {
				eventConsumer.accept(event);
			} catch (RuntimeException e) {
				LOG.warn("Filesystem event consumer failed with exception when processing event {}", event, e);
			}
		};
	}
}
