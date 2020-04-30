package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.CryptoFileSystemScoped;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextDirectory;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.ClosedFileSystemException;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

@CryptoFileSystemScoped
public class DirectoryStreamFactory {

	private final CryptoPathMapper cryptoPathMapper;
	private final DirectoryStreamComponent.Builder directoryStreamComponentBuilder; // sharing reusable builder via synchronized
	private final Map<CryptoDirectoryStream, DirectoryStream> streams = new HashMap<>();

	private volatile boolean closed = false;

	@Inject
	public DirectoryStreamFactory(CryptoPathMapper cryptoPathMapper, DirectoryStreamComponent.Builder directoryStreamComponentBuilder) {
		this.cryptoPathMapper = cryptoPathMapper;
		this.directoryStreamComponentBuilder = directoryStreamComponentBuilder;
	}

	public synchronized CryptoDirectoryStream newDirectoryStream(CryptoPath cleartextDir, Filter<? super Path> filter) throws IOException {
		if (closed) {
			throw new ClosedFileSystemException();
		}
		CiphertextDirectory ciphertextDir = cryptoPathMapper.getCiphertextDir(cleartextDir);
		DirectoryStream<Path> ciphertextDirStream = Files.newDirectoryStream(ciphertextDir.path);
		CryptoDirectoryStream cleartextDirStream = directoryStreamComponentBuilder //
				.dirId(ciphertextDir.dirId) //
				.ciphertextDirectoryStream(ciphertextDirStream) //
				.cleartextPath(cleartextDir) //
				.filter(filter) //
				.onClose(streams::remove) //
				.build() //
				.directoryStream();
		streams.put(cleartextDirStream, ciphertextDirStream);
		return cleartextDirStream;
	}

	public synchronized void close() throws IOException {
		closed = true;
		IOException exception = new IOException("Close failed");
		Iterator<Map.Entry<CryptoDirectoryStream, DirectoryStream>> iter = streams.entrySet().iterator();
		while (iter.hasNext()) {
			Map.Entry<CryptoDirectoryStream, DirectoryStream> entry = iter.next();
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
