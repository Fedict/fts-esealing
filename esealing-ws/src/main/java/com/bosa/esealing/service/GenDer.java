package com.bosa.esealing.service;

/**
 * Static methods for generating ASN.1-DER data.
 */
public class GenDer {

	/** Make a DER object, e.g.
	 * <pre>
	 *   make(0x02, new byte[] {0x01, 0x00, 0x01})   ->  {0x02, 0x03, 0x01, 0x00, 0x01}
	 * </pre>
	 */
	public static byte[] make(int tag, byte[] val) {

		int valLen = val.length;
		int lenLen = (valLen < 128) ? 1 : ((valLen < 256) ? 2 : 3);
		int tagLen = (tag < 256) ? 1 : 2;

		byte[] ret = new byte[tagLen + lenLen + valLen];
		int offs = 0;

		// tag
		if (tag >= 256)
			ret[offs++] = (byte) (tag / 256);
		ret[offs++] = (byte) tag;

		// length
		if (1 ==lenLen)
			ret[offs++] = (byte) valLen;
		else if (2 == lenLen) {
			ret[offs++] = (byte) 0x81;
			ret[offs++] = (byte) valLen;
		}
		else {
			ret[offs++] = (byte) 0x82;
			ret[offs++] = (byte) (valLen / 256);
			ret[offs++] = (byte) valLen;
		}

		// value
		System.arraycopy(val, 0, ret, offs, valLen);

		return ret;
	}

	/** 'extraByte': is pre-pended to 'val', usefull for a BIT STRING */
	public static byte[] make(int tag, byte extraByte, byte[] val) {

		byte[] tmp = new byte[val.length + 1];
		tmp[0] = extraByte;
		System.arraycopy(val, 0, tmp, 1, val.length);
		return make(tag, tmp);
	}

	/**
	 * For SET, SEQUENCE etc..
	 * <pre>
	 *   byte[] res = GenDer.make(0x30, new byte[][] {
	 *                    GenDer.make(0x02, new byte[] {0x01}),
	 *                    GenDer.make(0x30, new byte[][] {
	 *                        GenDer.make(0x06, new byte[] {0x12, 0x34, 0x56}),
	 *                        GenDer.make(0x05, new byte[] {}),
	 *                    }),
	 *                });
	 * </pre>
	 */
	public static byte[] make(int tag, byte[][] vals) {

		int valCount = vals.length;
		int totLen = 0;
		for (int i = 0; i < valCount; i++)
			totLen += vals[i].length;

		byte[] ret = new byte[totLen];

		int offs = 0;
		for (int i = 0; i < valCount; i++) {
			System.arraycopy(vals[i], 0, ret, offs, vals[i].length);
			offs += vals[i].length;
		}

		return make(tag, ret);
	}

	/**
	 * Returns an OID (without tag and length).
	 * @param oidStr  string representation of an OID, e.g. "2 5 4 5" or "2.5.4.5"
	 */
	public static byte[] makeOid(String oidStr) {

		int len = 0;
		byte[] oid = new byte[50]; // should be more then long enough

		String[] parts = oidStr.split(oidStr.contains(".") ? "\\." : " ");
		if (parts.length < 2)
			throw new RuntimeException("\"" + oidStr + "\": doesn't seem to be an OID, or wrong format");

		oid[len++] = (byte) (40 * Long.parseLong(parts[0]) + Long.parseLong(parts[1]));
		for (int i = 2; i < parts.length; i++) {
			long number = Long.parseLong(parts[i]);
			// convert the number a byte array
			int count = 0;
			oid[len + count++] = (byte) (number % 128);
			while (number > 127) {
				number /= 128;
				oid[len + count++] = (byte) (0x80 | (number % 128));
			}

			// invert the byte array
			for (int j = 0; j < (count / 2); j++) {
				byte tmp = oid[len + j];
				oid[len + j] = oid[len + count - j - 1];
				oid[len + count - j - 1] = tmp;
			}
			len += count;
		}

		byte[] ret = new byte[len];
		System.arraycopy(oid, 0, ret, 0, len);
		return ret;
	}

	/////////////////////////////////////////////////////////////////////////////////////

	/* Return the length of the ASN.1 length field (1, 2 or 3 bytes) */
	static int DerLenLen(int len) {

		if (len < 128)
			return 1;
		else if (len < 256)
			return 2;
		else if (len < 65536)
			return 3;
		else
			throw new RuntimeException("Data is too large (" + len + " bytes!)");
	}

	/**
	 * Add [ASN.1 length || data] to outp, starting at outOffs
	 * E.g. if data = {0xAB, 0xCD, 0xEF} then add [0x03, 0xAB, 0xCD, 0xEF]
	 */
	static int addDer(byte[] data, byte[] out, int outOffs) {

		return addDer(data, 0, data.length, out, outOffs);
	}

	static int addDer(byte[] buf, int offs, int len, byte[] out, int outOffs) {

		// Add the ASN.1 length
		outOffs = addDerLen(len, out, outOffs);

		// Add the data itself
		System.arraycopy(buf, offs, out, outOffs, len);
		outOffs += len;

		return outOffs;
	}

	static int addDerLen(int len, byte[] out, int outOffs) {

		if (len < 128)
			out[outOffs++] = (byte) len;
		else if (len < 256) {
			out[outOffs++] = (byte) 0x81;
			out[outOffs++] = (byte) len;
		}
		else if (len < 65536) {
			out[outOffs++] = (byte) 0x82;
			out[outOffs++] = (byte) (len / 256);
			out[outOffs++] = (byte) (len % 256);
		}
		else
			throw new RuntimeException("data is too large (" + len + " bytes!)");

		return outOffs;
	}
}

