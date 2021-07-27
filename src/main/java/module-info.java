import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.health.api.HealthCheck;
import org.cryptomator.cryptofs.health.dirid.DirIdCheck;
import org.cryptomator.cryptofs.health.type.CiphertextFileTypeCheck;

import java.nio.file.spi.FileSystemProvider;

module org.cryptomator.cryptofs {
	requires transitive org.cryptomator.cryptolib;
	requires com.google.common;
	requires org.slf4j;
	requires dagger;
	requires com.auth0.jwt;

	// filename-based module required by dagger
	// we will probably need to live with this for a while:
	// https://github.com/javax-inject/javax-inject/issues/33
	// May be provided by another lib during runtime
	requires static javax.inject;

	exports org.cryptomator.cryptofs;
	exports org.cryptomator.cryptofs.common;
	exports org.cryptomator.cryptofs.health.api;
	exports org.cryptomator.cryptofs.migration;
	exports org.cryptomator.cryptofs.migration.api;

	uses HealthCheck;

	provides HealthCheck with DirIdCheck, CiphertextFileTypeCheck;
	provides FileSystemProvider with CryptoFileSystemProvider;
}