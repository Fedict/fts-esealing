package com.bosa.esealing.service;

import jakarta.xml.bind.DatatypeConverter;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestGenDer {

	@Test
	public void testmake() {

		assertEquals("0203010001", bin2hex(GenDer.make(0x02, new byte[] {0x01, 0x00, 0x01})));
		assertEquals("03050009090909", bin2hex(GenDer.make(0x03, (byte) 0x00, new byte[] {0x09, 0x09, 0x09, 0x09})));
		assertEquals("300706031234560500", bin2hex(
			GenDer.make(0x30, new byte[][] {
				GenDer.make(0x06, new byte[] {0x12, 0x34, 0x56}),
				GenDer.make(0x05, new byte[] {}),
			})));
	}

	@Test
	public void testGenDer() {

		byte[] outp = new byte[20];

		GenDer.addDer(new byte[] {0x11, 0x22, 0x33}, outp, 0);
		assertEquals("03112233", bin2hex(outp, 0, 4));

		GenDer.addDer(new byte[] {0x00, 0x11, 0x22, 0x33}, 1, 3, outp, 5);
		assertEquals("03112233", bin2hex(outp, 5, 4));
	}

	@Test
	public void testMakeOid() {

		assertEquals("2B0601040182371514", bin2hex(GenDer.makeOid("1 3 6 1 4 1 311 21 20")));
		assertEquals("2A864886F70D010101", bin2hex(GenDer.makeOid("1.2.840.113549.1.1.1")));
	}

	private static String bin2hex(byte[] ba) {
		return DatatypeConverter.printHexBinary(ba);
	}

	private static String bin2hex(byte[] ba, int off, int len) {
		byte[] tmp = new byte[len];
		System.arraycopy(ba, off, tmp, 0, len);
		return DatatypeConverter.printHexBinary(tmp);
	}
}

