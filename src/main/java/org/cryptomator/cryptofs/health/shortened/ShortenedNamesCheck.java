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
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Set;
import java.util.function.Consumer;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cryptomator.cryptofs.common.Constants.DEFLATED_FILE_SUFFIX;
import static org.cryptomator.cryptofs.common.Constants.INFLATED_FILE_NAME;

/**
 * Visits all c9s directories and checks if they all are valid shortened resource according the Cryptomator vault specification.
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
			Path nameFile = dir.resolve(INFLATED_FILE_NAME);

			final BasicFileAttributes attrs;
			try {
				attrs = Files.getFileAttributeView(nameFile, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
			} catch (NoSuchFileException e) {
				resultCollector.accept(new MissingLongName(dir));
				return;
			}
			if (!attrs.isRegularFile()) {
				resultCollector.accept(new MissingLongName(dir));
				return;
			} else if (attrs.size() > LongFileNameProvider.MAX_FILENAME_BUFFER_SIZE) {
				resultCollector.accept(new ObeseNameFile(nameFile, attrs.size()));
				return;
			}

			var longName = Files.readString(nameFile, UTF_8);

			var syntaxResult = checkSyntax(longName);
			if (syntaxResult == SyntaxResult.INVALID) {
				resultCollector.accept(new NotDecodableLongName(nameFile, longName));
				return;
			} else if (syntaxResult == SyntaxResult.TRAILING_BYTES) {
				resultCollector.accept(new TrailingBytesInNameFile(nameFile, longName));
				return;
			}

			var expectedShortName = deflate(longName);
			if (!dir.getFileName().toString().equals(expectedShortName)) {
				resultCollector.accept(new LongShortNamesMismatch(dir, expectedShortName));
			} else {
				resultCollector.accept(new ValidShortenedFile(dir));
			}
		}


		/**
		 * Determines if the string stored inside the name file is a base64url encoded ending with {@value Constants#CRYPTOMATOR_FILE_SUFFIX}.
		 *
		 * <em>visible for testing</em>
		 *
		 * @return {@link SyntaxResult} indicating if it is valid, invalid or affected by https://github.com/cryptomator/cryptofs/issues/121
		 */
		SyntaxResult checkSyntax(String toAnalyse) {
			int posObligatoryC9rString = toAnalyse.indexOf(Constants.CRYPTOMATOR_FILE_SUFFIX);
			if (posObligatoryC9rString == -1) {
				return SyntaxResult.INVALID;
			}

			var encryptedFileName = toAnalyse.substring(0, posObligatoryC9rString);
			if (!BASE64URL.canDecode(encryptedFileName)) {
				return SyntaxResult.INVALID;
			}

			if (toAnalyse.length() > posObligatoryC9rString + Constants.CRYPTOMATOR_FILE_SUFFIX.length()) {
				return SyntaxResult.TRAILING_BYTES;
			}

			return SyntaxResult.VALID;
		}

		enum SyntaxResult {
			VALID,
			INVALID,
			TRAILING_BYTES; //to indicate issue https://github.com/cryptomator/cryptofs/issues/121
		}

		//visible for testing
		String deflate(String longFileName) {
			byte[] longFileNameBytes = longFileName.getBytes(UTF_8);
			byte[] hash = MessageDigestSupplier.SHA1.get().digest(longFileNameBytes);
			return BASE64URL.encode(hash) + DEFLATED_FILE_SUFFIX;
		}

	}


}
