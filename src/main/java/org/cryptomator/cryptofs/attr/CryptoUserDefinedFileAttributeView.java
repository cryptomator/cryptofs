package org.cryptomator.cryptofs.attr;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.Symlinks;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.common.DecryptingReadableByteChannel;
import org.cryptomator.cryptolib.common.EncryptingWritableByteChannel;

import javax.inject.Inject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.file.LinkOption;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.util.List;

@AttributeViewScoped
final class CryptoUserDefinedFileAttributeView extends AbstractCryptoFileAttributeView implements UserDefinedFileAttributeView {

	private static final String PREFIX = "c9r.";

	private final Cryptor cryptor;

	@Inject
	public CryptoUserDefinedFileAttributeView(CryptoPath cleartextPath, CryptoPathMapper pathMapper, LinkOption[] linkOptions, Symlinks symlinks, Cryptor cryptor) {
		super(cleartextPath, pathMapper, linkOptions, symlinks);
		this.cryptor = cryptor;
	}

	@Override
	public String name() {
		return "user"; // as per contract
	}

	@Override
	public List<String> list() throws IOException {
		var ciphertextNames = getCiphertextAttributeView(UserDefinedFileAttributeView.class).list();
		return ciphertextNames.stream().filter(s -> s.startsWith(PREFIX)).map(this::decryptName).toList();
	}

	@Override
	public int size(String cleartextName) throws IOException {
		var ciphertextName = encryptName(cleartextName);
		var ciphertextSize = getCiphertextAttributeView(UserDefinedFileAttributeView.class).size(ciphertextName);
		return (int) cryptor.fileContentCryptor().cleartextSize(ciphertextSize) - cryptor.fileHeaderCryptor().headerSize();
	}

	@Override
	public int read(String cleartextName, ByteBuffer dst) throws IOException {
		var ciphertextName = encryptName(cleartextName);
		var view = getCiphertextAttributeView(UserDefinedFileAttributeView.class);
		int size = view.size(ciphertextName);
		var buf = ByteBuffer.allocate(size);
		view.read(ciphertextName, buf);
		buf.flip();

		try (var in = new ByteBufferInputStream(buf); //
			 var ciphertextChannel = Channels.newChannel(in); //
			 var cleartextChannel = new DecryptingReadableByteChannel(ciphertextChannel, cryptor, true)) {
			return cleartextChannel.read(dst);
		}
	}

	@Override
	public int write(String cleartextName, ByteBuffer src) throws IOException {
		var ciphertextName = encryptName(cleartextName);
		try (var out = new ByteArrayOutputStream();
			 var ciphertextChannel = Channels.newChannel(out); //
			 var cleartextChannel = new EncryptingWritableByteChannel(ciphertextChannel, cryptor)) {
			int size = cleartextChannel.write(src);
			var buf = ByteBuffer.wrap(out.toByteArray());
			getCiphertextAttributeView(UserDefinedFileAttributeView.class).write(ciphertextName, buf);
			return size;
		}
	}

	@Override
	public void delete(String cleartextName) throws IOException {
		var ciphertextName = encryptName(cleartextName);
		getCiphertextAttributeView(UserDefinedFileAttributeView.class).delete(ciphertextName);
	}

	private String encryptName(String cleartextName) {
		return PREFIX + cryptor.fileNameCryptor().encryptFilename(BaseEncoding.base64Url(), cleartextName);
	}

	private String decryptName(String ciphertextName) {
		assert ciphertextName.startsWith(PREFIX);
		return cryptor.fileNameCryptor().decryptFilename(BaseEncoding.base64Url(), ciphertextName.substring(PREFIX.length()));
	}

	// taken from https://stackoverflow.com/a/6603018/4014509
	private static class ByteBufferInputStream extends InputStream {

		ByteBuffer buf;

		public ByteBufferInputStream(ByteBuffer buf) {
			this.buf = buf;
		}

		public int read() throws IOException {
			if (!buf.hasRemaining()) {
				return -1;
			}
			return buf.get() & 0xFF;
		}

		public int read(byte[] bytes, int off, int len) throws IOException {
			if (!buf.hasRemaining()) {
				return -1;
			}

			len = Math.min(len, buf.remaining());
			buf.get(bytes, off, len);
			return len;
		}
	}

}
