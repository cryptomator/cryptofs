/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration;

import dagger.MapKey;
import dagger.Module;
import dagger.Provides;
import dagger.multibindings.IntoMap;
import org.cryptomator.cryptofs.common.FileSystemCapabilityChecker;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptofs.migration.v6.Version6Migrator;
import org.cryptomator.cryptofs.migration.v7.Version7Migrator;
import org.cryptomator.cryptofs.migration.v8.Version8Migrator;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Module
class MigrationModule {

	@Provides
	@IntoMap
	@MigratorKey(Migration.FIVE_TO_SIX)
	Migrator provideVersion6Migrator(Version6Migrator migrator) {
		return migrator;
	}

	@Provides
	@IntoMap
	@MigratorKey(Migration.SIX_TO_SEVEN)
	Migrator provideVersion7Migrator(Version7Migrator migrator) {
		return migrator;
	}

	@Provides
	@IntoMap
	@MigratorKey(Migration.SEVEN_TO_EIGHT)
	Migrator provideVersion8Migrator(Version8Migrator migrator) {
		return migrator;
	}

	@Documented
	@Target(METHOD)
	@Retention(RUNTIME)
	@MapKey
	public @interface MigratorKey {
		Migration value();
	}

}
