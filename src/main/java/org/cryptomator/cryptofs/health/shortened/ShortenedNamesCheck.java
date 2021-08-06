package org.cryptomator.cryptofs.health.shortened;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.LongFileNameProvider;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.CheckFailed;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptofs.health.api.HealthCheck;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Set;
import java.util.function.Consumer;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cryptomator.cryptofs.common.Constants.DEFLATED_FILE_SUFFIX;
import static org.cryptomator.cryptofs.common.Constants.INFLATED_FILE_NAME;

/**
 * TODO: doc doc doc
 * 			- the duckumentation duck
 * 		   __
 * 	   ___( o)>
 * 	   \ <_. )
 * 		`---'   hjw
 */
public class ShortenedNamesCheck implements HealthCheck {

	private static final Logger LOG = LoggerFactory.getLogger(ShortenedNamesCheck.class);
	private static final int MAX_TRAVERSAL_DEPTH = 3;
	private static final BaseEncoding BASE64URL = BaseEncoding.base64Url();

	@Override
	public String name() {
		return "Shortened Names Check";
	}

	@Override
	public void check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor, Consumer<DiagnosticResult> resultCollector) {

		// scan vault structure:
		var dataDirPath = pathToVault.resolve(Constants.DATA_DIR_NAME);
		var dirVisitor = new ShortenedNamesCheck.DirVisitor(resultCollector);
		try {
			Files.walkFileTree(dataDirPath, Set.of(), MAX_TRAVERSAL_DEPTH, dirVisitor);
		} catch (IOException e) {
			LOG.error("Traversal of data dir failed.", e);
			resultCollector.accept(new CheckFailed("Traversal of data dir failed. See log for details."));
		}
	}

	// visible for testing
	static class DirVisitor extends SimpleFileVisitor<Path> {

		private final Consumer<DiagnosticResult> resultCollector;

		public DirVisitor(Consumer<DiagnosticResult> resultCollector) {
			this.resultCollector = resultCollector;
		}

		@Override
		public FileVisitResult visitFile(Path dir, BasicFileAttributes attrs) throws IOException {
			var name = dir.getFileName().toString();
			if (attrs.isDirectory() && name.endsWith(Constants.DEFLATED_FILE_SUFFIX)) {
				checkShortenedName(dir);
			}
			return FileVisitResult.CONTINUE;
		}

		// visible for testing
		void checkShortenedName(Path dir) throws IOException {
			try {
				var longName = inflate(dir);
				var shortName = deflate(longName);
				if (!dir.getFileName().equals(shortName)) {
					resultCollector.accept(new LongShortNamesMismatch(dir));
				}
				//TODO: check if content of longName is decryptable
				// dirID is needed for that
			} catch (ResultAlreadyPresentException e) {
				resultCollector.accept(e.result);
			}
		}

		//copied from LongFileNameProvider
		String inflate(Path c9sPath) throws IOException, ResultAlreadyPresentException {
			Path nameFile = c9sPath.resolve(INFLATED_FILE_NAME);

			if (!Files.isRegularFile(nameFile, LinkOption.NOFOLLOW_LINKS)) {
				throw new ResultAlreadyPresentException(new MissingLongName(c9sPath));
			}

			try (SeekableByteChannel ch = Files.newByteChannel(nameFile, StandardOpenOption.READ)) {
				if (ch.size() > LongFileNameProvider.MAX_FILENAME_BUFFER_SIZE) {
					throw new ResultAlreadyPresentException(new ObeseNameFile(nameFile, ch.size()));
				}
				ByteBuffer buf = ByteBuffer.allocate((int) ch.size());
				ch.read(buf);
				buf.flip();
				return UTF_8.decode(buf).toString();
			}
		}

		public String deflate(String longFileName) {
			byte[] longFileNameBytes = longFileName.getBytes(UTF_8);
			byte[] hash = MessageDigestSupplier.SHA1.get().digest(longFileNameBytes);
			return BASE64URL.encode(hash) + DEFLATED_FILE_SUFFIX;
		}

	}

	private static class ResultAlreadyPresentException extends Exception {

		final DiagnosticResult result;

		ResultAlreadyPresentException(DiagnosticResult result) {
			this.result = result;
		}
	}

}
