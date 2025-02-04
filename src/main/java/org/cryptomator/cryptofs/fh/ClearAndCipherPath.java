package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.CryptoPath;

import java.nio.file.Path;

public record ClearAndCipherPath(CryptoPath cleartextPath, Path ciphertextPath) {

}
