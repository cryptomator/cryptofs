import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.cryptomator.cryptofs.health.api.HealthCheck;
import org.cryptomator.cryptofs.health.dirid.DirIdCheck;
import org.cryptomator.cryptofs.health.shortened.ShortenedNamesCheck;
import org.cryptomator.cryptofs.health.type.CiphertextFileTypeCheck;

import java.nio.file.spi.FileSystemProvider;

module org.cryptomator.cryptofs {
	requires transitive org.cryptomator.cryptolib;
	requires com.google.common;
	requires com.github.benmanes.caffeine;
	requires org.slf4j;
	requires dagger;
	requires com.auth0.jwt;

	requires javax.inject;
	requires jakarta.inject;
	requires java.compiler;

	exports org.cryptomator.cryptofs;
	exports org.cryptomator.cryptofs.event;
	exports org.cryptomator.cryptofs.common;
	exports org.cryptomator.cryptofs.health.api;
	exports org.cryptomator.cryptofs.migration;
	exports org.cryptomator.cryptofs.migration.api;

	uses HealthCheck;

	provides HealthCheck with DirIdCheck, CiphertextFileTypeCheck, ShortenedNamesCheck;
	provides FileSystemProvider with CryptoFileSystemProvider;
}