package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.CipherDir;
import org.cryptomator.cryptofs.CryptoFileSystemScoped;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.common.Constants;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.ClosedFileSystemException;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

@CryptoFileSystemScoped
public class DirectoryStreamFactory {

	private final CryptoPathMapper cryptoPathMapper;
	private final DirectoryStreamComponent.Factory directoryStreamComponentFactory;
	private final Map<CryptoDirectoryStream, DirectoryStream<Path>> streams = new HashMap<>();

	private volatile boolean closed = false;

	@Inject
	public DirectoryStreamFactory(CryptoPathMapper cryptoPathMapper, DirectoryStreamComponent.Factory directoryStreamComponentFactory) {
		this.cryptoPathMapper = cryptoPathMapper;
		this.directoryStreamComponentFactory = directoryStreamComponentFactory;
	}

	//TODO: is synchronized still needed? One reason was, that a dagger builder was used (replaced by thread safe factory)
	public synchronized CryptoDirectoryStream newDirectoryStream(CryptoPath cleartextDir, Filter<? super Path> filter) throws IOException {
		if (closed) {
			throw new ClosedFileSystemException();
		}
		CipherDir ciphertextDir = cryptoPathMapper.getCiphertextDir(cleartextDir);
		DirectoryStream<Path> ciphertextDirStream = Files.newDirectoryStream(ciphertextDir.contentDirPath(), this::matchesEncryptedContentPattern);
		var cleartextDirStream = directoryStreamComponentFactory.create(cleartextDir, ciphertextDir.dirId(), ciphertextDirStream, filter, streams::remove).directoryStream();
		streams.put(cleartextDirStream, ciphertextDirStream);
		return cleartextDirStream;
	}

	//visible for testing
	boolean matchesEncryptedContentPattern(Path path) {
		var tmp = path.getFileName().toString();
		return tmp.length() >= Constants.MIN_CIPHER_NAME_LENGTH //
				&& (tmp.endsWith(Constants.CRYPTOMATOR_FILE_SUFFIX) || tmp.endsWith(Constants.DEFLATED_FILE_SUFFIX));
	}

	public synchronized void close() throws IOException {
		closed = true;
		IOException exception = new IOException("Close failed");
		var iter = streams.entrySet().iterator();
		while (iter.hasNext()) {
			var entry = iter.next();
			iter.remove();
			try {
				entry.getKey().close();
			} catch (IOException e) {
				exception.addSuppressed(e);
			}
			try {
				entry.getValue().close();
			} catch (IOException e) {
				exception.addSuppressed(e);
			}
		}
		if (exception.getSuppressed().length > 0) {
			throw exception;
		}
	}

}
