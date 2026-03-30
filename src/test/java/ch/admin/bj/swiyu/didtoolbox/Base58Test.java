package ch.admin.bj.swiyu.didtoolbox;

/*
 * From https://github.com/multiformats/java-multibase/blob/master/src/test/java/io/ipfs/multibase/MultibaseTest.java
 *
 * MIT License
 *
 * Copyright (c) 2015 Ian Preston
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class Base58Test {

    private static Collection<Object[]> data() {
        return Arrays.asList(
                new Object[][]{
                        {
                                hexToBytes("1220120F6AF601D46E10B2D2E11ED71C55D25F3042C22501E41D1246E7A1E9D3D8EC"),
                                "QmPZ9gcCEpqKTo6aq61g2nXGUhM4iCL3ewB6LDXZCtioEB" // w/out multibase ('z') prefix
                        },
                        {
                                hexToBytes("1220BA8632EF1A07986B171B3C8FAF0F79B3EE01B6C30BBE15A13261AD6CB0D02E3A"),
                                "QmatmE9msSfkKxoffpHwNLNKgwZG8eT9Bud6YoPab52vpy" // w/out multibase ('z') prefix
                        },
                        {new byte[1], "1"}, // w/out multibase ('z') prefix
                        {new byte[2], "11"}, // w/out multibase ('z') prefix
                        {new byte[4], "1111"}, // w/out multibase ('z') prefix
                        {new byte[8], "11111111"}, // w/out multibase ('z') prefix
                        {new byte[16], "1111111111111111"}, // w/out multibase ('z') prefix
                        {new byte[32], "11111111111111111111111111111111"}, // w/out multibase ('z') prefix
                        {
                                hexToBytes("446563656e7472616c697a652065766572797468696e67212121"),
                                "36UQrhJq9fNDS7DiAHM9YXqDHMPfr4EMArvt" // w/out multibase ('z') prefix
                        },
                });
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}, {2}")
    void testEncode(byte[] raw, String encoded) {
        String output = Base58.encode(raw);
        assertEquals(encoded, output, String.format("Expected %s, but got %s", bytesToHex(raw), output));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}, {2}")
    void testDecode(byte[] raw, String encoded) {
        byte[] output = Base58.decode(encoded);
        assertArrayEquals(
                raw, output, String.format("Expected %s, but got %s", bytesToHex(raw), bytesToHex(output)));
    }

    // Copied from https://stackoverflow.com/a/140861
    private static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] =
                    (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // Copied from https://stackoverflow.com/a/9855338
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}