package org.cryptomator.cryptofs.migration;

import java.util.Map;

import org.cryptomator.cryptofs.migration.api.Migrator;

import dagger.Component;

@Component(modules = {MigrationModule.class})
interface TestMigrationComponent extends MigrationComponent {

	Map<Migration, Migrator> availableMigrators();

}
