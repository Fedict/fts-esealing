package com.zetes.projects.bosa.esealing.service;

import java.io.File;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.NoSuchElementException;

/**
 * Class for parsing ASN.1 DER data.
 * For example, to get the modulus of an RSA public key from an X.509 cert:
 * <pre>
 * byte[] certbytes = ...
 * java.math.BigInteger = (new Der(certbytes))                // Certificate
 *                          .getChild(0x30)                     // TBSCertificate
 *                            .getChild(0x30, 4)                  // SubjectPublicKeyInfo
 *                              .getChild(0x03)                     // subjectPublicKey
 *                                .getChild(0x30)                     // RSAPublicKey
 *                                  .getChild(0x02).getBigIntValue();   // modulus
 * </pre>
 * It is also possible to enumerate the child objects with these methods:
 * <pre>
 *   hasMoreElements()
 *   nextElement()
 *   resetChildEnumeration()
 * </pre>
 * The toString() method returns an ASN.1 dump but could be removed to safe space.
 */
public class Der implements Enumeration<Der> {

	private byte[] buf;
	private int tag;
	private int valueOffs;
	private int valueLen;
	private int nextChildOffs;

	/** Warning: 'buf' is not copied, so don't make any changes in it while using this Der object */
	public Der(byte[] buf) throws IllegalArgumentException {

		int[] res = parse(buf, 0, buf.length);

		this.buf = buf;
		this.tag = res[0];
		this.valueOffs = res[1];
		this.valueLen = res[2];
		this.nextChildOffs = this.valueOffs + (0x03 == this.tag ? 1 : 0);
	}

	/** Warning: 'buf' is not copied, so don't make any changes in it while using this Der object */
	public Der(byte[] buf, int offs, int len) throws IllegalArgumentException {

		int[] res = parse(buf, offs, len);

		this.buf = buf;
		this.tag = res[0];
		this.valueOffs = res[1];
		this.valueLen = res[2];
		this.nextChildOffs = this.valueOffs + (0x03 == this.tag ? 1 : 0);
	}

	private Der(byte[] buf, int tag, int valueOffs, int valueLen) {

		this.buf = buf;
		this.tag = tag;
		this.valueOffs = valueOffs;
		this.valueLen = valueLen;
		this.nextChildOffs = this.valueOffs + (0x03 == this.tag ? 1 : 0);
	}

	private static int[] parse(byte[] buf, int offs, int len) throws IllegalArgumentException {

		// Parse the tag, assume it's only 1 or 2 bytes long
		int lenOffs = offs + 1;
		int tag = ubyteToInt(buf[offs]);
		if ((tag & 0x1f) == 0x1f) {
			if (buf[offs + 1] < 0)
				throw new IllegalArgumentException("Only tags of 1 or 2 bytes long are supported");
			tag = 256 * tag + ubyteToInt(buf[offs + 1]);
			lenOffs++;
		}

		// Parse the length, assume it's only 1, 2 or 3 bytes long
		int valueLen = buf[lenOffs];
		int valueOffs = 0;
		if (valueLen >= 0) {
			valueOffs = lenOffs + 1;
		}
		else if ((byte) 0x81 == valueLen) {
			valueLen = ubyteToInt(buf[lenOffs + 1]);
			valueOffs = lenOffs + 2;
		}
		else if ((byte) 0x82 == valueLen) {
			valueLen = 256 * ubyteToInt(buf[lenOffs + 1]) + ubyteToInt(buf[lenOffs + 2]);
			valueOffs = lenOffs + 3;
		}
		else if ((byte) 0x83 == valueLen) {
			valueLen = 256 * 256 * ubyteToInt(buf[lenOffs + 1]) + 256 * ubyteToInt(buf[lenOffs + 2]) + ubyteToInt(buf[lenOffs + 3]);
			valueOffs = lenOffs + 4;
		}
		else
			throw new IllegalArgumentException("Only lengths of 1, 2, 3 or 4 bytes long are supported (offset = " + (offs + 1) + ")");

		// Check if the DER object fits into the provided input
		if (offs + len < valueOffs + valueLen) {
			throw new IllegalArgumentException("Value exceed buffer size: " + valueLen +
				" bytes from offset + " + valueOffs + " but only " + (offs + len) + " available");
		}

		return new int[] {tag, valueOffs, valueLen};
	}

	private static int ubyteToInt(byte b) {

		return (int) (b < 0 ? (b + 256) : b);
	}

	/** Return the raw tag byte(s) */
	public int getTag() {

		return tag;
	}

	/** Return the value length */
	public int getValueLen() {

		return valueLen;
	}

	/** Return the value as a long value */
	public long getLongValue() throws IllegalArgumentException {

		if (0 == valueLen)
			throw new IllegalArgumentException("No value present (length = 0)");
		else if (valueLen > 8)
			throw new IllegalArgumentException("Value to large (" + valueLen + " bytes) to fit into a long");

		long ret = ubyteToInt(buf[valueOffs]);
		for (int i = 1; i < valueLen; i++) {
			ret = 256 * ret + ubyteToInt(buf[valueOffs + i]);
		}

		return ret;
	}

	/** Return the value as a BigInteger */
	public BigInteger getBigIntValue() throws IllegalArgumentException {

		if (0 == valueLen)
			throw new IllegalArgumentException("No value present (length = 0)");

		return new BigInteger(getBytesValue());
	}

	/** Return the value as a byte array */
	public byte[] getBytesValue() {

		byte[] ret = new byte[valueLen];
		System.arraycopy(buf, valueOffs, ret, 0, valueLen);

		return ret;
	}

	/** Return the value as a 'bit string' an (array of booleans). E.g. '04 30' => 0011b = {false, false, true, true} */
	public boolean[] getBitStringValue() {

		if (valueLen < 2)
			throw new IllegalArgumentException("BITSTRING value must be at least 2 bytes long");
		
		int unusedBits = buf[valueOffs];
		if (unusedBits > 7)
			throw new IllegalArgumentException("'unused bits' = " + unusedBits + " (must be < 8)");

		boolean ret[] = new boolean[8 * (valueLen - 1) - unusedBits];
		byte b = 0;
		for (int i = 0; i < ret.length; i++) {
			if (0 == i % 8)
				b = buf[valueOffs + 1 + (i / 8)];
			else
				b <<= 1;
			ret[i] = (b < 0); // means that msb == 1
		}

		return ret;
	}

	/** Return the value as OID string, e.g. "2 5 4 3" */
	public String getOidValue() throws IllegalArgumentException {

		if (0 == valueLen)
			throw new IllegalArgumentException("No value present (length = 0)");

		StringBuffer sb = new StringBuffer(50);

		int firstByte = ubyteToInt(buf[valueOffs]);
		sb.append(firstByte / 40);
		sb.append(" ").append(firstByte % 40);
		int val = 0;
		for (int i = 1; i < valueLen; i++) {
			byte b = buf[valueOffs + i];
			if (b < 0)
				val = 128 * val + (b & 0x7f);
			else {
				val = 128 * val + b;
				sb.append(".").append(val);
				val = 0;
			}
		}

		return sb.toString();
	}

	/** Copy the value into the 'buf' at offset 'offs' */
	public void copyValue(byte[] buf, int offs) {

		System.arraycopy(this.buf, this.valueOffs, buf, offs, this.valueLen);
	}

	/** Returns the full DER element (tag, length, value) */
	public byte[] getEncoded() {

		int tagLen = (tag < 256) ? 1 : 2;
		int lenLen = 1;
		if (valueLen >= 256*256) lenLen = 4;
		else if (valueLen >= 256) lenLen = 3;
		else if (valueLen >= 128) lenLen = 2;

		byte[] encoded = new byte[tagLen + lenLen + valueLen];
		System.arraycopy(buf, valueOffs - tagLen - lenLen, encoded, 0, encoded.length);
		return encoded;
	}

	//////////// For constructed objects (sequence, set, octet string encapsulating other objects, ..) ////////////////

	/**
	 * Returns the first child DER object, or null if not present
	 * @param tag   the tag that the child object should have, or 0 if the tag doesn't matter
	 */
	public Der getChild(int tag) {

		return getChild(tag, 0);
	}

	/**
	 * Returns a child DER object, or null if not present
	 * @param tag   the tag that the child object should have, or 0 if the tag doesn't matter
	 * @param skip  if skip == 0 then the first child is returned, if skip == 1 then the second child is returned, etc.
	 */
	public Der getChild(int tag, int skip) {

		if (0x03 == this.tag) {
			valueOffs++;
			valueLen--;
		}

		try {
			for (int i = valueOffs; i < valueOffs + valueLen; ) {
				int[] res = parse(buf, i, valueLen);
				if (0 == tag || res[0] == tag) {
					if (0 >= skip)
						return new Der(buf, res[0], res[1], res[2]);
					else
						skip--;
				}
				i = res[1] + res[2];
			}
		}
		catch (Exception e) {
		}
		finally {
			if (0x03 == this.tag) {
				valueOffs--;
				valueLen++;
			}
		}

		return null; // child not found
	}

	/** Returns true if this Der object can have more children */
	public boolean hasMoreElements() {

		return (nextChildOffs < valueOffs + valueLen);
	}

	/** Returns the next child Der object */
	public Der nextElement() throws NoSuchElementException {

		try {
			int[] res = parse(buf, nextChildOffs, valueLen);
			nextChildOffs = res[1] + res[2];
			return new Der(buf, res[0], res[1], res[2]);
		}
		catch (Exception e) {
			throw new NoSuchElementException(e.toString());
		}
	}

	/** Resets the enumeration for cildren, so hasMoreElements() and nextElement() can be used again */
	public void resetChildEnumeration() {

		nextChildOffs = valueOffs + (0x03 == tag ? 1 : 0);		
	}
}
