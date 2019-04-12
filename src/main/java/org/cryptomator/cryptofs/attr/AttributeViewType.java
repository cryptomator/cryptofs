package org.cryptomator.cryptofs.attr;

import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.util.Arrays;
import java.util.Optional;

public enum AttributeViewType {
	BASIC(BasicFileAttributeView.class, "basic"),
	OWNER(FileOwnerAttributeView.class, "owner"),
	POSIX(PosixFileAttributeView.class, "posix"),
	DOS(DosFileAttributeView.class, "dos");

	private final Class<? extends FileAttributeView> type;
	private final String viewName;

	AttributeViewType(Class<? extends FileAttributeView> type, String viewName) {
		this.type = type;
		this.viewName = viewName;
	}

	/**
	 * @return The {@link java.nio.file.attribute.AttributeView#name() name} of the AttributeView
	 */
	public String getViewName() {
		return viewName;
	}

	/**
	 * @return The class of the AttributeView
	 */
	public Class<? extends FileAttributeView> getType() {
		return type;
	}

	public static Optional<AttributeViewType> getByType(Class<? extends FileAttributeView> type) {
		return Arrays.stream(values()).filter(v -> type.isAssignableFrom(v.type)).findAny();
	}

	public static Optional<AttributeViewType> getByName(String viewName) {
		return Arrays.stream(values()).filter(v -> v.viewName.equals(viewName)).findAny();
	}
}
