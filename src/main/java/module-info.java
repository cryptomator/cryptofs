import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.cryptomator.cryptofs.health.api.HealthCheck;
import org.cryptomator.cryptofs.health.dirid.DirIdCheck;

import java.nio.file.spi.FileSystemProvider;

module org.cryptomator.cryptofs {
	requires transitive org.cryptomator.cryptolib;
	requires com.google.common;
	requires org.slf4j;

	/* TODO: filename-based modules: */
	requires java.jwt;
	requires dagger;
	requires static javax.inject; // probably no longer needed if dagger is an automatic module (but might require --patch-module in case of split packages)

	exports org.cryptomator.cryptofs;
	exports org.cryptomator.cryptofs.common;
	exports org.cryptomator.cryptofs.health.api;
	exports org.cryptomator.cryptofs.migration;
	exports org.cryptomator.cryptofs.migration.api;

	uses HealthCheck;

	provides HealthCheck with DirIdCheck;
	provides FileSystemProvider with CryptoFileSystemProvider;
}