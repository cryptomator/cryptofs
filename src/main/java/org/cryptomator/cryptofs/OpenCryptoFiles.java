package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.OpenCryptoFile.anOpenCryptoFile;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.cryptomator.cryptofs.OpenCryptoFile.AlreadyClosedException;
import org.cryptomator.cryptolib.api.Cryptor;

class OpenCryptoFiles {

	private final ConcurrentMap<Object,OpenCryptoFile> openCryptoFiles = new ConcurrentHashMap<>();
	
	public OpenCryptoFile get(Path ciphertextPath, Cryptor cryptor, EffectiveOpenOptions options) throws IOException {
		Object id = idOf(ciphertextPath);
		while (true) {
			try {
				return tryToGetOpenCryptoFile(id, cryptor, ciphertextPath, options);
			} catch (AlreadyClosedException e) {
				openCryptoFiles.remove(id);
			} catch (IOExceptionWrapper e) {
				throw e.getCause();
			}
		}
	}

	private Object idOf(Path ciphertextPath) throws IOException {
		FileSystemProvider provider = ciphertextPath.getFileSystem().provider();
		Object id = provider.readAttributes(ciphertextPath, BasicFileAttributes.class).fileKey();
		if (id == null) {
			id = ciphertextPath.toAbsolutePath().normalize();
		}
		return id;
	}

	private OpenCryptoFile tryToGetOpenCryptoFile(Object id, Cryptor cryptor, Path ciphertextPath, EffectiveOpenOptions options) throws AlreadyClosedException, IOException {
		OpenCryptoFile.Builder builder = openCryptoFileBuilder(id, cryptor, ciphertextPath, options);
		OpenCryptoFile openCryptoFile = openCryptoFiles.computeIfAbsent(id, ignored -> IOExceptionWrapper.wrapExceptionOf(builder::build));
		openCryptoFile.open(options);
		return openCryptoFile;
	}

	private OpenCryptoFile.Builder openCryptoFileBuilder(Object id, Cryptor cryptor, Path ciphertextPath, EffectiveOpenOptions options) {
		return anOpenCryptoFile()
			.withId(id)
			.withCryptor(cryptor)
			.withCyphertextPath(ciphertextPath)
			.withOptions(options)
			.onClosed(closed -> openCryptoFiles.remove(closed.id()));
	}
	
	private static class IOExceptionWrapper extends RuntimeException {
		
		public IOExceptionWrapper(Exception cause) {
			super(cause);
		}
		
		public static <T> T wrapExceptionOf(SupplierThrowingException<T,IOException> supplier) {
			return supplier.wrapExceptionUsing(IOExceptionWrapper::new).get();
		}

		@Override
		public synchronized IOException getCause() {
			return (IOException)super.getCause();
		}
		
	}
	
}
