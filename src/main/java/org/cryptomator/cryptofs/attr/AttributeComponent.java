package org.cryptomator.cryptofs.attr;

import dagger.BindsInstance;
import dagger.Subcomponent;
import org.cryptomator.cryptofs.common.CiphertextFileType;

import javax.inject.Named;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;

@AttributeScoped
@Subcomponent(modules = {AttributeModule.class})
public interface AttributeComponent {

	@Named("cleartext")
	BasicFileAttributes attributes();

	default <T extends BasicFileAttributes> T attributes(Class<T> type) {
		var attr = attributes();
		if (type.isInstance(attr)) {
			return type.cast(attr);
		} else {
			throw new UnsupportedOperationException("Unsupported file attribute type: " + type);
		}
	}

	@Subcomponent.Factory
	interface Factory {

		AttributeComponent create(@BindsInstance Path ciphertextPath, //
								  @BindsInstance CiphertextFileType ciphertextFileType, //
								  @BindsInstance @Named("ciphertext") BasicFileAttributes ciphertextAttributes);

	}
}
