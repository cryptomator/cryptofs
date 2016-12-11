package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.file.ClosedFileSystemException;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.inject.Inject;

import org.cryptomator.cryptofs.CryptoPathMapper.Directory;
import org.cryptomator.cryptolib.api.Cryptor;

@PerFileSystem
class DirectoryStreamFactory {

	private final Cryptor cryptor;
	private final LongFileNameProvider longFileNameProvider;
	private final CryptoPathMapper cryptoPathMapper;
	private final FinallyUtil finallyUtil;

	private final ConcurrentMap<CryptoDirectoryStream, CryptoDirectoryStream> streams = new ConcurrentHashMap<>();

	private volatile boolean closed = false;

	@Inject
	public DirectoryStreamFactory(Cryptor cryptor, LongFileNameProvider longFileNameProvider, CryptoPathMapper cryptoPathMapper, FinallyUtil finallyUtil) {
		this.cryptor = cryptor;
		this.longFileNameProvider = longFileNameProvider;
		this.cryptoPathMapper = cryptoPathMapper;
		this.finallyUtil = finallyUtil;
	}

	public DirectoryStream<Path> newDirectoryStream(CryptoPath cleartextDir, Filter<? super Path> filter) throws IOException {
		Directory ciphertextDir = cryptoPathMapper.getCiphertextDir(cleartextDir);
		CryptoDirectoryStream stream = new CryptoDirectoryStream( //
				ciphertextDir, //
				cleartextDir, //
				cryptor.fileNameCryptor(), //
				longFileNameProvider, //
				filter, //
				closed -> streams.remove(closed), //
				finallyUtil);
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
