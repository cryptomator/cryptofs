package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.util.HashMap;
import java.util.Map;

class CryptoFileAttributeViewProvider {

	private final Map<Class<? extends FileAttributeView>, AttributeViewProvider<? extends FileAttributeView>> attributeProviders = new HashMap<>();
	private final CryptoFileAttributeProvider fileAttributeProvider;

	public CryptoFileAttributeViewProvider(CryptoFileAttributeProvider fileAttributeProvider) {
		attributeProviders.put(BasicFileAttributeView.class, (AttributeViewProvider<BasicFileAttributeView>) CryptoBasicFileAttributeView::new);
		attributeProviders.put(PosixFileAttributeView.class, (AttributeViewProvider<PosixFileAttributeView>) CryptoPosixFileAttributeView::new);
		attributeProviders.put(DosFileAttributeView.class, (AttributeViewProvider<DosFileAttributeView>) CryptoDosFileAttributeView::new);
		this.fileAttributeProvider = fileAttributeProvider;
	}

	@SuppressWarnings("unchecked")
	public <A extends FileAttributeView> A getAttributeView(Path ciphertextPath, Class<A> type) throws IOException {
		if (attributeProviders.containsKey(type)) {
			AttributeViewProvider<A> provider = (AttributeViewProvider<A>) attributeProviders.get(type);
			return provider.provide(ciphertextPath, fileAttributeProvider);
		} else {
			throw new UnsupportedOperationException("Unsupported file attribute type: " + type);
		}
	}

	@FunctionalInterface
	private static interface AttributeViewProvider<A extends FileAttributeView> {
		A provide(Path ciphertextPath, CryptoFileAttributeProvider fileAttributeProvider);
	}

}
