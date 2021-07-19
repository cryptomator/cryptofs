/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration;

import dagger.BindsInstance;
import dagger.Component;

import java.security.SecureRandom;

@Component(modules = {MigrationModule.class})
interface MigrationComponent {

	Migrators migrators();

	@Component.Builder
	interface Builder {

		@BindsInstance
		Builder csprng(SecureRandom csprng);

		MigrationComponent build();
	}

}
