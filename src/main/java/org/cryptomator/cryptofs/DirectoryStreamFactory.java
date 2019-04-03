package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.file.ClosedFileSystemException;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.inject.Inject;

import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextDirectory;
import org.cryptomator.cryptolib.api.Cryptor;

@CryptoFileSystemScoped
class DirectoryStreamFactory {

	private final Cryptor cryptor;
	private final LongFileNameProvider longFileNameProvider;
	private final ConflictResolver conflictResolver;
	private final CryptoPathMapper cryptoPathMapper;
	private final FinallyUtil finallyUtil;
	private final EncryptedNamePattern encryptedNamePattern;

	private final ConcurrentMap<CryptoDirectoryStream, CryptoDirectoryStream> streams = new ConcurrentHashMap<>();

	private volatile boolean closed = false;

	@Inject
	public DirectoryStreamFactory(Cryptor cryptor, LongFileNameProvider longFileNameProvider, ConflictResolver conflictResolver, CryptoPathMapper cryptoPathMapper, FinallyUtil finallyUtil,
			EncryptedNamePattern encryptedNamePattern) {
		this.cryptor = cryptor;
		this.longFileNameProvider = longFileNameProvider;
		this.conflictResolver = conflictResolver;
		this.cryptoPathMapper = cryptoPathMapper;
		this.finallyUtil = finallyUtil;
		this.encryptedNamePattern = encryptedNamePattern;
	}

	public CryptoDirectoryStream newDirectoryStream(CryptoPath cleartextDir, Filter<? super Path> filter) throws IOException {
		CiphertextDirectory ciphertextDir = cryptoPathMapper.getCiphertextDir(cleartextDir);
		CryptoDirectoryStream stream = new CryptoDirectoryStream( //
				ciphertextDir, //
				cleartextDir, //
				cryptor.fileNameCryptor(), //
				cryptoPathMapper, //
				longFileNameProvider, //
				conflictResolver, //
				filter, //
				closed -> streams.remove(closed), //
				finallyUtil, //
				encryptedNamePattern);
		streams.put(stream, stream);
		if (closed) {
			stream.close();
			throw new ClosedFileSystemException();
		}
		return stream;
	}

	public void close() throws IOException {
		closed = true;
		finallyUtil.guaranteeInvocationOf( //
				streams.keySet().stream() //
						.map(stream -> (RunnableThrowingException<IOException>) () -> stream.close()) //
						.iterator());
	}

}
