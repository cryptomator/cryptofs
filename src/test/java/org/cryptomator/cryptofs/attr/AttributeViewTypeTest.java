package org.cryptomator.cryptofs.attr;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.file.attribute.FileAttributeView;

public class AttributeViewTypeTest {

	@DisplayName("test AttributeViewType.getByName(...)")
	@ParameterizedTest
	@EnumSource(AttributeViewType.class)
	public void testGetByName(AttributeViewType expectedType) {
		String name = expectedType.getViewName();
		AttributeViewType result = AttributeViewType.getByName(name).get();
		Assertions.assertSame(expectedType, result);
	}

	@DisplayName("test AttributeViewType.getByType(...)")
	@ParameterizedTest
	@EnumSource(AttributeViewType.class)
	public void testGetByType(AttributeViewType expectedType) {
		Class<? extends FileAttributeView> clazz = expectedType.getType();
		AttributeViewType result = AttributeViewType.getByType(clazz).get();
		Assertions.assertSame(expectedType, result);
	}

}
