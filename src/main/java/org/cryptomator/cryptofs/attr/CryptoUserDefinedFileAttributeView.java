package org.cryptomator.cryptofs.attr;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.Symlinks;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.common.ByteBuffers;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.LinkOption;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@AttributeViewScoped
public class CryptoUserDefinedFileAttributeView extends AbstractCryptoFileAttributeView implements UserDefinedFileAttributeView {

	private static final BaseEncoding NAME_ENCODING = BaseEncoding.base64Url();
	private static final String NAME_PREFIX = "user.cryptomator.";

	private final Cryptor cryptor;

	@Inject
	public CryptoUserDefinedFileAttributeView(Cryptor cryptor, CryptoPath cleartextPath, CryptoPathMapper pathMapper, LinkOption[] linkOptions, Symlinks symlinks, OpenCryptoFiles openCryptoFiles) {
		super(cleartextPath, pathMapper, linkOptions, symlinks, openCryptoFiles);
		this.cryptor = cryptor;
	}

	private String encryptName(String cleartextName) {
		return NAME_PREFIX + cryptor.fileNameCryptor().encryptFilename(NAME_ENCODING, cleartextName);
	}

	private Optional<String> decryptName(String ciphertextName) {
		if (ciphertextName.startsWith(NAME_PREFIX)) {
			String ciphertext = ciphertextName.substring(NAME_PREFIX.length());
			try {
				return Optional.of(cryptor.fileNameCryptor().decryptFilename(NAME_ENCODING, ciphertext));
			} catch (AuthenticationFailedException e) {
				return Optional.empty();
			}
		} else {
			return Optional.empty();
		}
	}

	private ByteBuffer encryptContent(ByteBuffer cleartext) {
		return cleartext; // TODO
	}

	private ByteBuffer decryptContent(ByteBuffer ciphertext) {
		return ciphertext; // TODO
	}

	private int cleartextSize(int ciphertextSize) {
		return ciphertextSize; // TODO
	}

	@Override
	public List<String> list() throws IOException {
		return getCiphertextAttributeView(UserDefinedFileAttributeView.class).list() //
				.stream() //
				.map(this::decryptName) //
				.filter(Optional::isPresent) //
				.map(Optional::get) //
				.collect(Collectors.toList());
	}

	@Override
	public int size(String name) throws IOException {
		int ciphertextSize = getCiphertextAttributeView(UserDefinedFileAttributeView.class).size(encryptName(name));
		return cleartextSize(ciphertextSize);
	}

	@Override
	public int read(String name, ByteBuffer dst) throws IOException {
		UserDefinedFileAttributeView delegate = getCiphertextAttributeView(UserDefinedFileAttributeView.class);
		String ciphertextName = encryptName(name);
		ByteBuffer ciphertextBuf = ByteBuffer.allocate(delegate.size(ciphertextName));
		int read = delegate.read(encryptName(name), ciphertextBuf);
		assert read == ciphertextBuf.capacity();
		ciphertextBuf.flip();
		ByteBuffer cleartextBuf = decryptContent(ciphertextBuf);
		return ByteBuffers.copy(cleartextBuf, dst);
	}

	@Override
	public int write(String name, ByteBuffer src) throws IOException {
		int cleartextLength = src.remaining();
		int ciphertextWritten = getCiphertextAttributeView(UserDefinedFileAttributeView.class).write(encryptName(name), encryptContent(src));
		assert cleartextLength == cleartextSize(ciphertextWritten);
		return cleartextLength;
	}

	@Override
	public void delete(String name) throws IOException {
		getCiphertextAttributeView(UserDefinedFileAttributeView.class).delete(encryptName(name));
	}

	@Override
	public String name() {
		return "user";
	}
}
