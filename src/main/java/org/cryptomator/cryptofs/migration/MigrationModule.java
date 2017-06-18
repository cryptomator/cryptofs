/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptofs.migration.v6.Version6Migrator;
import org.cryptomator.cryptolib.CryptoLibModule;

import dagger.MapKey;
import dagger.Module;
import dagger.Provides;
import dagger.multibindings.IntoMap;

@Module(includes = {CryptoLibModule.class})
class MigrationModule {

	@Provides
	@IntoMap
	@MigratorKey(Migration.FIVE_TO_SIX)
	Migrator provideVersion6Migrator(Version6Migrator migrator) {
		return migrator;
	}

	// @Provides
	// @IntoMap
	// @MigratorKey(Migration.SIX_TO_SEVEN)
	// Migrator provideVersion7Migrator(Version7Migrator migrator) {
	// return migrator;
	// }
	//
	// @Provides
	// @IntoMap
	// @MigratorKey(Migration.FIVE_TO_SEVEN)
	// Migrator provideVersion7Migrator(Version6Migrator v6Migrator, Version7Migrator v7Migrator) {
	// return v6Migrator.andThen(v7Migrator);
	// }

	@Documented
	@Target(METHOD)
	@Retention(RUNTIME)
	@MapKey
	public @interface MigratorKey {
		Migration value();
	}

}
