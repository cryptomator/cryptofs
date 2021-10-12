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

	@Subcomponent.Builder
	interface Builder {

		@BindsInstance
		Builder ciphertextPath(Path ciphertextPath);

		@BindsInstance
		Builder ciphertextFileType(CiphertextFileType ciphertextFileType);

		@BindsInstance
		Builder ciphertextAttributes(@Named("ciphertext") BasicFileAttributes ciphertextAttributes);

		AttributeComponent build();
	}
}
