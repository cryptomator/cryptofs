package org.cryptomator.cryptofs.dir;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Needs to be compiled via maven as the JMH annotation processor needs to do stuff...
 */
public class Base64UrlRegexTest {

	private static final String[] TEST_INPUTS = { //
			"aaaaBBBBccccDDDDeeeeFFFF",
			"aaaaBBBBccccDDDDeeeeFFF=",
			"aaaaBBBBccccDDDDeeeeFF==",
			"aaaaBBBBcc0123456789_-==",
			"aaaaBBBBccccDDDDeeeeFFFFggggHH==",
			"-3h6-FSsYhMCJHSAV9cjJ89F7R73b0zIB4vvO01b7uWq28fWioRagWpMv-w0MA-2ORjbShuv", //
			"iJYw7QpVjKTDv_b6H5jLkauVrnPcGbV9DnIG426EBzjlYmRuJDX5cjFJLmTDA7EOEmo5rAHT3Jc=", //
			"PnBpirtqhCKm9hE1341rxkqdASfyYJqNHROxR1xJWDH6TGbeqqXn_sr2Rk5zzVpSbufkiqZH9a==", //
			"S8cmirjkHBHbIJZXExbFyyTOA8r6TvTPddK_sdQZpcE3RCMDI0mo9w2f53DSkqT0xRf1xcrmxvU=" //
	};

	private static final String[] TEST_INVALID_INPUTS = { //
			"aaaaBBBBccccDDDDeeee", // too short
			"aaaaBBBBccccDDDDeeeeFFF", // unpadded
			"====BBBBccccDDDDeeeeFFFF", // padding not at end
			"????BBBBccccDDDDeeeeFFFF", // invalid chars
			"conflict aaaaBBBBccccDDDDeeeeFFFF", // only a partial match
			"aaaaBBBBccccDDDDeeeeFFFF conflict", // only a partial match
			"-3h6-FSsYhMCJHSAV9cjJ89F7R73b0zIB4vvO01b7uWq28fWioRagWpMv-w0MA-2ORjbShu", // not multiple of four
			"=iJYw7QpVjKTDv_b6H5jLkauVrnPcGbV9DnIG426EBzjlYmRuJDX5cjFJLmTDA7EOEmo5rAHT3J=", // padding in wrong position
			"PnBp.irtqhCKm9hE1341rxkqdASfyYJqNHROxR1xJWDH6TGbeqqXn_sr2Rk5zzVpSbufkiqZH9a==", // invalid character
	};

	@ParameterizedTest
	@ValueSource(strings = {
			"([a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_]{20}[a-zA-Z0-9-_=]{4}",
			"[a-zA-Z0-9-_]{20}([a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_=]{4}",
			"[a-zA-Z0-9-_]{20}([a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_=]{4}",
			"[a-zA-Z0-9-_]{20}(?:[a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_=]{4}",
			"[a-zA-Z0-9-_]{20}(?:[a-zA-Z0-9-_]{4})*(?:[a-zA-Z0-9-_]{4}|[a-zA-Z0-9-_]{3}=|[a-zA-Z0-9-_]{2}==)", // most strict
			"[a-zA-Z0-9-_]{20}(?:[a-zA-Z0-9-_=]{4})+", // most permissive
	})
	public void testValidBase64Pattern(String patternString) {
		Pattern pattern = Pattern.compile(patternString);
		for (String input : TEST_INPUTS) {
			Matcher matcher = pattern.matcher(input);
			Assertions.assertTrue(matcher.matches(), "pattern does not match " + input);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = {
			"([a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_]{20}[a-zA-Z0-9-_=]{4}",
			"[a-zA-Z0-9-_]{20}([a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_=]{4}",
			"[a-zA-Z0-9-_]{20}([a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_=]{4}",
			"[a-zA-Z0-9-_]{20}(?:[a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_=]{4}",
			"[a-zA-Z0-9-_]{20}(?:[a-zA-Z0-9-_]{4})*(?:[a-zA-Z0-9-_]{4}|[a-zA-Z0-9-_]{3}=|[a-zA-Z0-9-_]{2}==)", // most strict
			"[a-zA-Z0-9-_]{20}(?:[a-zA-Z0-9-_=]{4})+", // most permissive
	})
	public void testInvalidInputs(String patternString) {
		Pattern pattern = Pattern.compile(patternString);
		for (String input : TEST_INVALID_INPUTS) {
			Matcher matcher = pattern.matcher(input);
			Assertions.assertFalse(matcher.matches(), "pattern matches " + input);
		}
	}

	@Test
	@Disabled // only run manually
	public void runBenchmarks() throws RunnerException {
		// Taken from http://stackoverflow.com/a/30486197/4014509:
		Options opt = new OptionsBuilder().include(RegexBenchmark.class.getSimpleName()).build();
		new Runner(opt).run();
	}

	@State(Scope.Thread)
	@Fork(3)
	@Warmup(iterations = 2, time = 500, timeUnit = TimeUnit.MILLISECONDS)
	@Measurement(iterations = 3, time = 500, timeUnit = TimeUnit.MILLISECONDS)
	@BenchmarkMode(value = {Mode.AverageTime})
	@OutputTimeUnit(TimeUnit.MICROSECONDS)
	public static class RegexBenchmark {

		// Base64 regex pattern
		@Param({
				"([a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_]{20}[a-zA-Z0-9-_=]{4}",
				"[a-zA-Z0-9-_]{20}([a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_=]{4}",
				"[a-zA-Z0-9-_]{20}([a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_=]{4}",
				"[a-zA-Z0-9-_]{20}(?:[a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_=]{4}",
				"[a-zA-Z0-9-_]{20}(?:[a-zA-Z0-9-_]{4})*(?:[a-zA-Z0-9-_]{4}|[a-zA-Z0-9-_]{3}=|[a-zA-Z0-9-_]{2}==)", // most strict
				"[a-zA-Z0-9-_]{20}(?:[a-zA-Z0-9-_=]{4})+", // most permissive
		})
		private String patternString;

		private Pattern pattern;

		@Setup(Level.Trial)
		public void compilePattern() {
			pattern = Pattern.compile(patternString);
		}

		@Benchmark
		public void testPattern(Blackhole bh) {
			for (String input : TEST_INPUTS) {
				Matcher matcher = pattern.matcher(input);
				bh.consume(matcher.matches());
			}
		}

	}
}