package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Set;

class CryptoPosixFileAttributeView extends CryptoBasicFileAttributeView implements PosixFileAttributeView {

	public CryptoPosixFileAttributeView(Path ciphertextPath, CryptoFileAttributeProvider fileAttributeProvider) {
		super(ciphertextPath, fileAttributeProvider);
	}

	@Override
	public String name() {
		return "posix";
	}

	@Override
	public PosixFileAttributes readAttributes() throws IOException {
		return fileAttributeProvider.readAttributes(ciphertextPath, PosixFileAttributes.class);
	}

	@Override
	public UserPrincipal getOwner() throws IOException {
		return readAttributes().owner();
	}

	@Override
	public void setOwner(UserPrincipal owner) throws IOException {
		Files.getFileAttributeView(ciphertextPath, PosixFileAttributeView.class).setOwner(owner);
	}

	@Override
	public void setPermissions(Set<PosixFilePermission> perms) throws IOException {
		Files.getFileAttributeView(ciphertextPath, PosixFileAttributeView.class).setPermissions(perms);
	}

	@Override
	public void setGroup(GroupPrincipal group) throws IOException {
		Files.getFileAttributeView(ciphertextPath, PosixFileAttributeView.class).setGroup(group);
	}

}
