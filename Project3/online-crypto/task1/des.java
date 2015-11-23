// ----------------------------------------------------------------------------
// $Id: DES.java,v 1.3 2003/10/05 03:41:38 raif Exp $
//
// Copyright (C) 2002, 2003 Free Software Foundation, Inc.
//
// This file is part of GNU Crypto.
//
// GNU Crypto is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2, or (at your option)
// any later version.
//
// GNU Crypto is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; see the file COPYING.  If not, write to the
//
//    Free Software Foundation Inc.,
//    59 Temple Place - Suite 330,
//    Boston, MA 02111-1307
//    USA
//
// Linking this library statically or dynamically with other modules is
// making a combined work based on this library.  Thus, the terms and
// conditions of the GNU General Public License cover the whole
// combination.
//
// As a special exception, the copyright holders of this library give
// you permission to link this library with independent modules to
// produce an executable, regardless of the license terms of these
// independent modules, and to copy and distribute the resulting
// executable under terms of your choice, provided that you also meet,
// for each linked independent module, the terms and conditions of the
// license of that module.  An independent module is a module which is
// not derived from or based on this library.  If you modify this
// library, you may extend this exception to your version of the
// library, but you are not obligated to do so.  If you do not wish to
// do so, delete this exception statement from your version.
//
// --------------------------------------------------------------------------

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;

/**
 * <p>The Data Encryption Standard. DES is a 64-bit block cipher with a 56-bit
 * key, developed by IBM in the 1970's for the standardization process begun by
 * the National Bureau of Standards (now NIST).</p>
 *
 * <p>New applications should not use DES except for compatibility.</p>
 *
 * <p>This version is based upon the description and sample implementation in
 * [1].</p>
 *
 * <p>References:</p>
 * <ol>
 *    <li>Bruce Schneier, <i>Applied Cryptography: Protocols, Algorithms, and
 *    Source Code in C, Second Edition</i>. (1996 John Wiley and Sons) ISBN
 *    0-471-11709-9. Pages 265--301, 623--632.</li>
 * </ol>
 *
 * @version $Revision: 1.3 $
 */
class DES extends BaseCipher {

    // Constants and variables
    // -------------------------------------------------------------------------

    /** DES operates on 64 bit blocks. */
    public static final int BLOCK_SIZE = 8;

    /** DES uses 56 bits of a 64 bit parity-adjusted key. */
    public static final int KEY_SIZE = 8;

    // S-Boxes 1 through 8.
    private static final int[] SP1 = new int[] {
            0x01010400, 0x00000000, 0x00010000, 0x01010404,
            0x01010004, 0x00010404, 0x00000004, 0x00010000,
            0x00000400, 0x01010400, 0x01010404, 0x00000400,
            0x01000404, 0x01010004, 0x01000000, 0x00000004,
            0x00000404, 0x01000400, 0x01000400, 0x00010400,
            0x00010400, 0x01010000, 0x01010000, 0x01000404,
            0x00010004, 0x01000004, 0x01000004, 0x00010004,
            0x00000000, 0x00000404, 0x00010404, 0x01000000,
            0x00010000, 0x01010404, 0x00000004, 0x01010000,
            0x01010400, 0x01000000, 0x01000000, 0x00000400,
            0x01010004, 0x00010000, 0x00010400, 0x01000004,
            0x00000400, 0x00000004, 0x01000404, 0x00010404,
            0x01010404, 0x00010004, 0x01010000, 0x01000404,
            0x01000004, 0x00000404, 0x00010404, 0x01010400,
            0x00000404, 0x01000400, 0x01000400, 0x00000000,
            0x00010004, 0x00010400, 0x00000000, 0x01010004
    };

    private static final int[] SP2 = new int[] {
            0x80108020, 0x80008000, 0x00008000, 0x00108020,
            0x00100000, 0x00000020, 0x80100020, 0x80008020,
            0x80000020, 0x80108020, 0x80108000, 0x80000000,
            0x80008000, 0x00100000, 0x00000020, 0x80100020,
            0x00108000, 0x00100020, 0x80008020, 0x00000000,
            0x80000000, 0x00008000, 0x00108020, 0x80100000,
            0x00100020, 0x80000020, 0x00000000, 0x00108000,
            0x00008020, 0x80108000, 0x80100000, 0x00008020,
            0x00000000, 0x00108020, 0x80100020, 0x00100000,
            0x80008020, 0x80100000, 0x80108000, 0x00008000,
            0x80100000, 0x80008000, 0x00000020, 0x80108020,
            0x00108020, 0x00000020, 0x00008000, 0x80000000,
            0x00008020, 0x80108000, 0x00100000, 0x80000020,
            0x00100020, 0x80008020, 0x80000020, 0x00100020,
            0x00108000, 0x00000000, 0x80008000, 0x00008020,
            0x80000000, 0x80100020, 0x80108020, 0x00108000
    };

    private static final int[] SP3 = new int[] {
            0x00000208, 0x08020200, 0x00000000, 0x08020008,
            0x08000200, 0x00000000, 0x00020208, 0x08000200,
            0x00020008, 0x08000008, 0x08000008, 0x00020000,
            0x08020208, 0x00020008, 0x08020000, 0x00000208,
            0x08000000, 0x00000008, 0x08020200, 0x00000200,
            0x00020200, 0x08020000, 0x08020008, 0x00020208,
            0x08000208, 0x00020200, 0x00020000, 0x08000208,
            0x00000008, 0x08020208, 0x00000200, 0x08000000,
            0x08020200, 0x08000000, 0x00020008, 0x00000208,
            0x00020000, 0x08020200, 0x08000200, 0x00000000,
            0x00000200, 0x00020008, 0x08020208, 0x08000200,
            0x08000008, 0x00000200, 0x00000000, 0x08020008,
            0x08000208, 0x00020000, 0x08000000, 0x08020208,
            0x00000008, 0x00020208, 0x00020200, 0x08000008,
            0x08020000, 0x08000208, 0x00000208, 0x08020000,
            0x00020208, 0x00000008, 0x08020008, 0x00020200
    };

    private static final int[] SP4 = new int[] {
            0x00802001, 0x00002081, 0x00002081, 0x00000080,
            0x00802080, 0x00800081, 0x00800001, 0x00002001,
            0x00000000, 0x00802000, 0x00802000, 0x00802081,
            0x00000081, 0x00000000, 0x00800080, 0x00800001,
            0x00000001, 0x00002000, 0x00800000, 0x00802001,
            0x00000080, 0x00800000, 0x00002001, 0x00002080,
            0x00800081, 0x00000001, 0x00002080, 0x00800080,
            0x00002000, 0x00802080, 0x00802081, 0x00000081,
            0x00800080, 0x00800001, 0x00802000, 0x00802081,
            0x00000081, 0x00000000, 0x00000000, 0x00802000,
            0x00002080, 0x00800080, 0x00800081, 0x00000001,
            0x00802001, 0x00002081, 0x00002081, 0x00000080,
            0x00802081, 0x00000081, 0x00000001, 0x00002000,
            0x00800001, 0x00002001, 0x00802080, 0x00800081,
            0x00002001, 0x00002080, 0x00800000, 0x00802001,
            0x00000080, 0x00800000, 0x00002000, 0x00802080
    };

    private static final int[] SP5 = new int[] {
            0x00000100, 0x02080100, 0x02080000, 0x42000100,
            0x00080000, 0x00000100, 0x40000000, 0x02080000,
            0x40080100, 0x00080000, 0x02000100, 0x40080100,
            0x42000100, 0x42080000, 0x00080100, 0x40000000,
            0x02000000, 0x40080000, 0x40080000, 0x00000000,
            0x40000100, 0x42080100, 0x42080100, 0x02000100,
            0x42080000, 0x40000100, 0x00000000, 0x42000000,
            0x02080100, 0x02000000, 0x42000000, 0x00080100,
            0x00080000, 0x42000100, 0x00000100, 0x02000000,
            0x40000000, 0x02080000, 0x42000100, 0x40080100,
            0x02000100, 0x40000000, 0x42080000, 0x02080100,
            0x40080100, 0x00000100, 0x02000000, 0x42080000,
            0x42080100, 0x00080100, 0x42000000, 0x42080100,
            0x02080000, 0x00000000, 0x40080000, 0x42000000,
            0x00080100, 0x02000100, 0x40000100, 0x00080000,
            0x00000000, 0x40080000, 0x02080100, 0x40000100
    };

    private static final int[] SP6 = new int[] {
            0x20000010, 0x20400000, 0x00004000, 0x20404010,
            0x20400000, 0x00000010, 0x20404010, 0x00400000,
            0x20004000, 0x00404010, 0x00400000, 0x20000010,
            0x00400010, 0x20004000, 0x20000000, 0x00004010,
            0x00000000, 0x00400010, 0x20004010, 0x00004000,
            0x00404000, 0x20004010, 0x00000010, 0x20400010,
            0x20400010, 0x00000000, 0x00404010, 0x20404000,
            0x00004010, 0x00404000, 0x20404000, 0x20000000,
            0x20004000, 0x00000010, 0x20400010, 0x00404000,
            0x20404010, 0x00400000, 0x00004010, 0x20000010,
            0x00400000, 0x20004000, 0x20000000, 0x00004010,
            0x20000010, 0x20404010, 0x00404000, 0x20400000,
            0x00404010, 0x20404000, 0x00000000, 0x20400010,
            0x00000010, 0x00004000, 0x20400000, 0x00404010,
            0x00004000, 0x00400010, 0x20004010, 0x00000000,
            0x20404000, 0x20000000, 0x00400010, 0x20004010
    };

    private static final int[] SP7 = new int[] {
            0x00200000, 0x04200002, 0x04000802, 0x00000000,
            0x00000800, 0x04000802, 0x00200802, 0x04200800,
            0x04200802, 0x00200000, 0x00000000, 0x04000002,
            0x00000002, 0x04000000, 0x04200002, 0x00000802,
            0x04000800, 0x00200802, 0x00200002, 0x04000800,
            0x04000002, 0x04200000, 0x04200800, 0x00200002,
            0x04200000, 0x00000800, 0x00000802, 0x04200802,
            0x00200800, 0x00000002, 0x04000000, 0x00200800,
            0x04000000, 0x00200800, 0x00200000, 0x04000802,
            0x04000802, 0x04200002, 0x04200002, 0x00000002,
            0x00200002, 0x04000000, 0x04000800, 0x00200000,
            0x04200800, 0x00000802, 0x00200802, 0x04200800,
            0x00000802, 0x04000002, 0x04200802, 0x04200000,
            0x00200800, 0x00000000, 0x00000002, 0x04200802,
            0x00000000, 0x00200802, 0x04200000, 0x00000800,
            0x04000002, 0x04000800, 0x00000800, 0x00200002
    };

    private static final int[] SP8 = new int[] {
            0x10001040, 0x00001000, 0x00040000, 0x10041040,
            0x10000000, 0x10001040, 0x00000040, 0x10000000,
            0x00040040, 0x10040000, 0x10041040, 0x00041000,
            0x10041000, 0x00041040, 0x00001000, 0x00000040,
            0x10040000, 0x10000040, 0x10001000, 0x00001040,
            0x00041000, 0x00040040, 0x10040040, 0x10041000,
            0x00001040, 0x00000000, 0x00000000, 0x10040040,
            0x10000040, 0x10001000, 0x00041040, 0x00040000,
            0x00041040, 0x00040000, 0x10041000, 0x00001000,
            0x00000040, 0x10040040, 0x00001000, 0x00041040,
            0x10001000, 0x00000040, 0x10000040, 0x10040000,
            0x10040040, 0x10000000, 0x00040000, 0x10001040,
            0x00000000, 0x10041040, 0x00040040, 0x10000040,
            0x10040000, 0x10001000, 0x10001040, 0x00000000,
            0x10041040, 0x00041000, 0x00041000, 0x00001040,
            0x00001040, 0x00040040, 0x10000000, 0x10041000
    };

    /**
     * Constants that help in determining whether or not a byte array is parity
     * adjusted.
     */
    private static final byte[] PARITY = {
            8,1,0,8,0,8,8,0,0,8,8,0,8,0,2,8,0,8,8,0,8,0,0,8,8,0,0,8,0,8,8,3,
            0,8,8,0,8,0,0,8,8,0,0,8,0,8,8,0,8,0,0,8,0,8,8,0,0,8,8,0,8,0,0,8,
            0,8,8,0,8,0,0,8,8,0,0,8,0,8,8,0,8,0,0,8,0,8,8,0,0,8,8,0,8,0,0,8,
            8,0,0,8,0,8,8,0,0,8,8,0,8,0,0,8,0,8,8,0,8,0,0,8,8,0,0,8,0,8,8,0,
            0,8,8,0,8,0,0,8,8,0,0,8,0,8,8,0,8,0,0,8,0,8,8,0,0,8,8,0,8,0,0,8,
            8,0,0,8,0,8,8,0,0,8,8,0,8,0,0,8,0,8,8,0,8,0,0,8,8,0,0,8,0,8,8,0,
            8,0,0,8,0,8,8,0,0,8,8,0,8,0,0,8,0,8,8,0,8,0,0,8,8,0,0,8,0,8,8,0,
            4,8,8,0,8,0,0,8,8,0,0,8,0,8,8,0,8,5,0,8,0,8,8,0,0,8,8,0,8,0,6,8
    };

    // Key schedule constants.

    private static final byte[] ROTARS = {
            1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
    };

    private static final byte[] PC1 = {
            56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,
            9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35,
            62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 29, 21,
            13,  5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3
    };

    private static final byte[] PC2 = {
            13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
            22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
            40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
            43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
    };

    /**
     * Weak keys (parity adjusted): If all the bits in each half are either 0
     * or 1, then the key used for any cycle of the algorithm is the same as
     * all other cycles.
     */
    public static final byte[][] WEAK_KEYS = {
            Util.toBytesFromString("0101010101010101"),
            Util.toBytesFromString("01010101FEFEFEFE"),
            Util.toBytesFromString("FEFEFEFE01010101"),
            Util.toBytesFromString("FEFEFEFEFEFEFEFE")
    };

    /**
     * Semi-weak keys (parity adjusted):  Some pairs of keys encrypt plain text
     * to identical cipher text. In other words, one key in the pair can decrypt
     * messages that were encrypted with the other key. These keys are called
     * semi-weak keys. This occurs because instead of 16 different sub-keys being
     * generated, these semi-weak keys produce only two different sub-keys.
     */
    public static final byte[][] SEMIWEAK_KEYS = {
            Util.toBytesFromString("01FE01FE01FE01FE"), Util.toBytesFromString("FE01FE01FE01FE01"),
            Util.toBytesFromString("1FE01FE00EF10EF1"), Util.toBytesFromString("E01FE01FF10EF10E"),
            Util.toBytesFromString("01E001E001F101F1"), Util.toBytesFromString("E001E001F101F101"),
            Util.toBytesFromString("1FFE1FFE0EFE0EFE"), Util.toBytesFromString("FE1FFE1FFE0EFE0E"),
            Util.toBytesFromString("011F011F010E010E"), Util.toBytesFromString("1F011F010E010E01"),
            Util.toBytesFromString("E0FEE0FEF1FEF1FE"), Util.toBytesFromString("FEE0FEE0FEF1FEF1")
    };

    /** Possible weak keys (parity adjusted) --produce 4 instead of 16 subkeys. */
    public static final byte[][] POSSIBLE_WEAK_KEYS = {
            Util.toBytesFromString("1F1F01010E0E0101"),
            Util.toBytesFromString("011F1F01010E0E01"),
            Util.toBytesFromString("1F01011F0E01010E"),
            Util.toBytesFromString("01011F1F01010E0E"),
            Util.toBytesFromString("E0E00101F1F10101"),
            Util.toBytesFromString("FEFE0101FEFE0101"),
            Util.toBytesFromString("FEE01F01FEF10E01"),
            Util.toBytesFromString("E0FE1F01F1FE0E01"),
            Util.toBytesFromString("FEE0011FFEF1010E"),
            Util.toBytesFromString("E0FE011FF1FE010E"),
            Util.toBytesFromString("E0E01F1FF1F10E0E"),
            Util.toBytesFromString("FEFE1F1FFEFE0E0E"),
            Util.toBytesFromString("1F1F01010E0E0101"),
            Util.toBytesFromString("011F1F01010E0E01"),
            Util.toBytesFromString("1F01011F0E01010E"),
            Util.toBytesFromString("01011F1F01010E0E"),
            Util.toBytesFromString("01E0E00101F1F101"),
            Util.toBytesFromString("1FFEE0010EFEF001"),
            Util.toBytesFromString("1FE0FE010EF1FE01"),
            Util.toBytesFromString("01FEFE0101FEFE01"),
            Util.toBytesFromString("1FE0E01F0EF1F10E"),
            Util.toBytesFromString("01FEE01F01FEF10E"),
            Util.toBytesFromString("01E0FE1F01F1FE0E"),
            Util.toBytesFromString("1FFEFE1F0EFEFE0E"),

            Util.toBytesFromString("E00101E0F10101F1"),
            Util.toBytesFromString("FE1F01E0FE0E0EF1"),
            Util.toBytesFromString("FE011FE0FE010EF1"),
            Util.toBytesFromString("E01F1FE0F10E0EF1"),
            Util.toBytesFromString("FE0101FEFE0101FE"),
            Util.toBytesFromString("E01F01FEF10E01FE"),
            Util.toBytesFromString("E0011FFEF1010EFE"),
            Util.toBytesFromString("FE1F1FFEFE0E0EFE"),
            Util.toBytesFromString("1FFE01E00EFE01F1"),
            Util.toBytesFromString("01FE1FE001FE0EF1"),
            Util.toBytesFromString("1FE001FE0EF101FE"),
            Util.toBytesFromString("01E01FFE01F10EFE"),
            Util.toBytesFromString("0101E0E00101F1F1"),
            Util.toBytesFromString("1F1FE0E00E0EF1F1"),
            Util.toBytesFromString("1F01FEE00E01FEF1"),
            Util.toBytesFromString("011FFEE0010EFEF1"),
            Util.toBytesFromString("1F01E0FE0E01F1FE"),
            Util.toBytesFromString("011FE0FE010EF1FE"),
            Util.toBytesFromString("0101FEFE0001FEFE"),
            Util.toBytesFromString("1F1FFEFE0E0EFEFE"),
            Util.toBytesFromString("FEFEE0E0FEFEF1F1"),
            Util.toBytesFromString("E0FEFEE0F1FEFEF1"),
            Util.toBytesFromString("FEE0E0FEFEF1F1FE"),
            Util.toBytesFromString("E0E0FEFEF1F1FEFE")
    };

    // Constructor(s)
    // -------------------------------------------------------------------------

    /** Default 0-argument constructor. */
    public DES() {
        super("des", BLOCK_SIZE, KEY_SIZE);
    }

    // Class methods
    // -------------------------------------------------------------------------

    /**
     * <p>Adjust the parity for a raw key array. This essentially means that each
     * byte in the array will have an odd number of '1' bits (the last bit in
     * each byte is unused.</p>
     *
     * @param kb The key array, to be parity-adjusted.
     * @param offset The starting index into the key bytes.
     */
    public static void adjustParity(byte[] kb, int offset) {
        for (int i = offset; i < KEY_SIZE; i++) {
            kb[i] ^= (PARITY[kb[i] & 0xff] == 8) ? 1 : 0;
        }
    }

    /**
     * <p>Test if a byte array, which must be at least 8 bytes long, is parity
     * adjusted.</p>
     *
     * @param kb The key bytes.
     * @param offset The starting index into the key bytes.
     * @return <code>true</code> if the first 8 bytes of <i>kb</i> have been
     * parity adjusted. <code>false</code> otherwise.
     */
    public static boolean isParityAdjusted(byte[] kb, int offset) {
        int w = 0x88888888;
        int n = PARITY[kb[offset+0] & 0xff]; n <<= 4;
        n |= PARITY[kb[offset+1] & 0xff]; n <<= 4;
        n |= PARITY[kb[offset+2] & 0xff]; n <<= 4;
        n |= PARITY[kb[offset+3] & 0xff]; n <<= 4;
        n |= PARITY[kb[offset+4] & 0xff]; n <<= 4;
        n |= PARITY[kb[offset+5] & 0xff]; n <<= 4;
        n |= PARITY[kb[offset+6] & 0xff]; n <<= 4;
        n |= PARITY[kb[offset+7] & 0xff];
        return (n & w) == 0;
    }

    /**
     * <p>Test if a key is a weak key.</p>
     *
     * @param kb The key to test.
     * @return <code>true</code> if the key is weak.
     */
    public static boolean isWeak(byte[] kb) {
//      return Arrays.equals(kb, WEAK_KEYS[0]) || Arrays.equals(kb, WEAK_KEYS[1])
//          || Arrays.equals(kb, WEAK_KEYS[2]) || Arrays.equals(kb, WEAK_KEYS[3])
//          || Arrays.equals(kb, WEAK_KEYS[4]) || Arrays.equals(kb, WEAK_KEYS[5])
//          || Arrays.equals(kb, WEAK_KEYS[6]) || Arrays.equals(kb, WEAK_KEYS[7]);
        for (int i = 0; i < WEAK_KEYS.length; i++) {
            if (Arrays.equals(WEAK_KEYS[i], kb)) {
                return true;
            }
        }
        return false;
    }

    /**
     * <p>Test if a key is a semi-weak key.</p>
     *
     * @param kb The key to test.
     * @return <code>true</code> if this key is semi-weak.
     */
    public static boolean isSemiWeak(byte[] kb) {
//      return Arrays.equals(kb, SEMIWEAK_KEYS[0])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[1])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[2])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[3])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[4])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[5])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[6])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[7])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[8])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[9])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[10])
//          || Arrays.equals(kb, SEMIWEAK_KEYS[11]);
        for (int i = 0; i < SEMIWEAK_KEYS.length; i++) {
            if (Arrays.equals(SEMIWEAK_KEYS[i], kb)) {
                return true;
            }
        }
        return false;
    }

    /**
     * <p>Test if the designated byte array represents a possibly weak key.</p>
     *
     * @param kb the byte array to test.
     * @return <code>true</code> if <code>kb</code>represents a possibly weak key.
     * Returns <code>false</code> otherwise.
     */
    public static boolean isPossibleWeak(byte[] kb) {
        for (int i = 0; i < POSSIBLE_WEAK_KEYS.length; i++) {
            if (Arrays.equals(POSSIBLE_WEAK_KEYS[i], kb)) {
                return true;
            }
        }
        return false;
    }

    /**
     * <p>The core DES function. This is used for both encryption and decryption,
     * the only difference being the key.</p>
     *
     * @param in The input bytes.
     * @param i The starting offset into the input bytes.
     * @param out The output bytes.
     * @param o The starting offset into the output bytes.
     * @param key The working key.
     */
    private static void desFunc(byte[] in, int i, byte[] out, int o, int[] key) {
        int right, left, work;

        // Load.
        left  = (in[i++] & 0xff) << 24 | (in[i++] & 0xff) << 16
                | (in[i++] & 0xff) <<  8 |  in[i++] & 0xff;
        right = (in[i++] & 0xff) << 24 | (in[i++] & 0xff) << 16
                | (in[i++] & 0xff) <<  8 |  in[i  ] & 0xff;

        // Initial permutation.
        work  = ((left >>>  4) ^ right) & 0x0F0F0F0F;
        left  ^= work << 4;
        right ^= work;

        work  = ((left >>> 16) ^ right) & 0x0000FFFF;
        left  ^= work << 16;
        right ^= work;

        work  = ((right >>>  2) ^ left) & 0x33333333;
        right ^= work << 2;
        left  ^= work;

        work  = ((right >>>  8) ^ left) & 0x00FF00FF;
        right ^= work << 8;
        left  ^= work;

        right = ((right << 1) | ((right >>> 31) & 1)) & 0xFFFFFFFF;
        work = (left ^ right) & 0xAAAAAAAA;
        left  ^= work;
        right ^= work;
        left = ((left << 1) | ((left >>> 31) & 1)) & 0xFFFFFFFF;

        int k = 0, t;
        for (int round = 0; round < 8; round++) {
            work = right >>> 4 | right << 28;
            work ^= key[k++];
            t  = SP7[work & 0x3F]; work >>>= 8;
            t |= SP5[work & 0x3F]; work >>>= 8;
            t |= SP3[work & 0x3F]; work >>>= 8;
            t |= SP1[work & 0x3F];
            work = right ^ key[k++];
            t |= SP8[work & 0x3F]; work >>>= 8;
            t |= SP6[work & 0x3F]; work >>>= 8;
            t |= SP4[work & 0x3F]; work >>>= 8;
            t |= SP2[work & 0x3F];
            left ^= t;

            work = left >>> 4 | left << 28;
            work ^= key[k++];
            t  = SP7[work & 0x3F]; work >>>= 8;
            t |= SP5[work & 0x3F]; work >>>= 8;
            t |= SP3[work & 0x3F]; work >>>= 8;
            t |= SP1[work & 0x3F];
            work = left ^ key[k++];
            t |= SP8[work & 0x3F]; work >>>= 8;
            t |= SP6[work & 0x3F]; work >>>= 8;
            t |= SP4[work & 0x3F]; work >>>= 8;
            t |= SP2[work & 0x3F];
            right ^= t;
        }

        // The final permutation.
        right = (right << 31) | (right >>> 1);
        work = (left ^ right) & 0xAAAAAAAA;
        left  ^= work;
        right ^= work;
        left = (left << 31) | (left >>> 1);

        work = ((left >>> 8) ^ right) & 0x00FF00FF;
        left ^= work << 8;
        right ^= work;

        work = ((left >>> 2) ^ right) & 0x33333333;
        left  ^= work << 2;
        right ^= work;

        work = ((right >>> 16) ^ left) & 0x0000FFFF;
        right ^= work << 16;
        left  ^= work;

        work = ((right >>> 4) ^ left) & 0x0F0F0F0F;
        right ^= work << 4;
        left  ^= work;

        out[o++] = (byte)(right >>> 24);
        out[o++] = (byte)(right >>> 16);
        out[o++] = (byte)(right >>>  8);
        out[o++] = (byte) right;
        out[o++] = (byte)(left >>> 24);
        out[o++] = (byte)(left >>> 16);
        out[o++] = (byte)(left >>>  8);
        out[o  ] = (byte) left;
    }

    // Instance methods implementing BaseCipher
    // -------------------------------------------------------------------------

    public Object clone() {
        return new DES();
    }

    public Iterator blockSizes() {
        return Collections.singleton(new Integer(BLOCK_SIZE)).iterator();
    }

    public Iterator keySizes() {
        return Collections.singleton(new Integer(KEY_SIZE)).iterator();
    }

    public Object makeKey(byte[] kb, int bs) throws InvalidKeyException {
        if (kb == null || kb.length != KEY_SIZE)
            throw new InvalidKeyException("DES keys must be 8 bytes long");

//      if (Properties.checkForWeakKeys()
        //          && (isWeak(kb) || isSemiWeak(kb) || isPossibleWeak(kb))) {
        //     throw new WeakKeyException();
        //  }

        int i, j, l, m, n;
        long pc1m = 0, pcr = 0;

        for (i = 0; i < 56; i++) {
            l = PC1[i];
            pc1m |= ((kb[l >>> 3] & (0x80 >>> (l & 7))) != 0)
                    ? (1L << (55 - i)) : 0;
        }

        Context ctx = new Context();

        // Encryption key first.
        for (i = 0; i < 16; i++) {
            pcr = 0;
            m = i << 1;
            n = m + 1;
            for (j = 0; j < 28; j++) {
                l = j + ROTARS[i];
                if (l < 28) pcr |= ((pc1m & 1L << (55 - l)) != 0)
                        ? (1L << (55 - j)) : 0;
                else pcr |= ((pc1m & 1L << (55 - (l - 28))) != 0)
                        ? (1L << (55 - j)) : 0;
            }
            for (j = 28; j < 56; j++) {
                l = j + ROTARS[i];
                if (l < 56) pcr |= ((pc1m & 1L << (55 - l)) != 0)
                        ? (1L << (55 - j)) : 0;
                else pcr |= ((pc1m & 1L << (55 - (l - 28))) != 0)
                        ? (1L << (55 - j)) : 0;
            }
            for (j = 0; j < 24; j++) {
                if ((pcr & 1L << (55 - PC2[j   ])) != 0) ctx.ek[m] |= 1 << (23 - j);
                if ((pcr & 1L << (55 - PC2[j+24])) != 0) ctx.ek[n] |= 1 << (23 - j);
            }
        }

        // The decryption key is the same, but in reversed order.
        for (i = 0; i < Context.EXPANDED_KEY_SIZE; i += 2) {
            ctx.dk[30 - i] = ctx.ek[i];
            ctx.dk[31 - i] = ctx.ek[i+1];
        }

        // "Cook" the keys.
        for (i = 0; i < 32; i += 2) {
            int x, y;

            x = ctx.ek[i  ];
            y = ctx.ek[i+1];

            ctx.ek[i  ] = ((x & 0x00FC0000)  <<  6) | ((x & 0x00000FC0)  << 10)
                    | ((y & 0x00FC0000) >>> 10) | ((y & 0x00000FC0) >>>  6);
            ctx.ek[i+1] = ((x & 0x0003F000)  << 12) | ((x & 0x0000003F)  << 16)
                    | ((y & 0x0003F000) >>>  4) |  (y & 0x0000003F);

            x = ctx.dk[i  ];
            y = ctx.dk[i+1];

            ctx.dk[i  ] = ((x & 0x00FC0000)  <<  6) | ((x & 0x00000FC0)  << 10)
                    | ((y & 0x00FC0000) >>> 10) | ((y & 0x00000FC0) >>>  6);
            ctx.dk[i+1] = ((x & 0x0003F000)  << 12) | ((x & 0x0000003F)  << 16)
                    | ((y & 0x0003F000) >>>  4) |  (y & 0x0000003F);
        }

        return ctx;
    }

    public String encrypt(Object K, byte[] in) {
        byte[] out = new byte[BLOCK_SIZE];
        desFunc(in, 0, out, 0, ((Context) K).ek);
        return Util.toString(out);
    }

    public String decrypt(Object K, byte[] in) {
        byte[] out = new byte[BLOCK_SIZE];
        desFunc(in, 0, out, 0, ((Context) K).dk);
        return Util.toString(out);
    }

    public void encrypt(byte[] in, int i, byte[] out, int o, Object K, int bs) {
        desFunc(in, i, out, o, ((Context) K).ek);
    }

    public void decrypt(byte[] in, int i, byte[] out, int o, Object K, int bs) {
        desFunc(in, i, out, o, ((Context) K).dk);
    }

    
    // Inner classe(s)

    /**
     * Simple wrapper class around the session keys. Package-private so TripleDES
     * can see it.
     */
    final class Context {

        // Constants and variables
        // ----------------------------------------------------------------------

        private static final int EXPANDED_KEY_SIZE = 32;

        /** The encryption key. */
        int[] ek;

        /** The decryption key. */
        int[] dk;

        // Constructor(s)
        // ----------------------------------------------------------------------

        /** Default 0-arguments constructor. */
        Context() {
            ek = new int[EXPANDED_KEY_SIZE];
            dk = new int[EXPANDED_KEY_SIZE];
        }

        // Class methods
        // ----------------------------------------------------------------------

        // Instance methods
        // ----------------------------------------------------------------------

        byte[] getEncryptionKeyBytes() {
            return toByteArray(ek);
        }

        byte[] getDecryptionKeyBytes() {
            return toByteArray(dk);
        }

        byte[] toByteArray(int[] k) {
            byte[] result = new byte[4 * k.length];
            for (int i = 0, j = 0; i < k.length; i++) {
                result[j++] = (byte)(k[i] >>> 24);
                result[j++] = (byte)(k[i] >>> 16);
                result[j++] = (byte)(k[i] >>>  8);
                result[j++] = (byte) k[i];
            }
            return result;
        }
    }
}

/**
 * <p>A collection of utility methods used throughout this project.</p>
 *
 * @version $Revision: 1.10 $
 */
class Util {

    // Constants and variables
    // -------------------------------------------------------------------------

    // Hex charset
    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

    // Base-64 charset
    private static final String BASE64_CHARS =
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./";
    private static final char[] BASE64_CHARSET = BASE64_CHARS.toCharArray();

    // Constructor(s)
    // -------------------------------------------------------------------------

    /** Trivial constructor to enforce Singleton pattern. */
    private Util() {
        super();
    }

    // Class methods
    // -------------------------------------------------------------------------

    /**
     * <p>Returns a string of hexadecimal digits from a byte array. Each byte is
     * converted to 2 hex symbols; zero(es) included.</p>
     *
     * <p>This method calls the method with same name and three arguments as:</p>
     *
     * <pre>
     *    toString(ba, 0, ba.length);
     * </pre>
     *
     * @param ba the byte array to convert.
     * @return a string of hexadecimal characters (two for each byte)
     * representing the designated input byte array.
     */
    public static String toString(byte[] ba) {
        return toString(ba, 0, ba.length);
    }

    /**
     * <p>Returns a string of hexadecimal digits from a byte array, starting at
     * <code>offset</code> and consisting of <code>length</code> bytes. Each byte
     * is converted to 2 hex symbols; zero(es) included.</p>
     *
     * @param ba the byte array to convert.
     * @param offset the index from which to start considering the bytes to
     * convert.
     * @param length the count of bytes, starting from the designated offset to
     * convert.
     * @return a string of hexadecimal characters (two for each byte)
     * representing the designated input byte sub-array.
     */
    public static final String toString(byte[] ba, int offset, int length) {
        char[] buf = new char[length * 2];
        for (int i = 0, j = 0, k; i < length; ) {
            k = ba[offset + i++];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
        }
        return new String(buf);
    }

    /**
     * <p>Returns a string of hexadecimal digits from a byte array. Each byte is
     * converted to 2 hex symbols; zero(es) included. The argument is
     * treated as a large little-endian integer and is returned as a
     * large big-endian integer.</p>
     *
     * <p>This method calls the method with same name and three arguments as:</p>
     *
     * <pre>
     *    toReversedString(ba, 0, ba.length);
     * </pre>
     *
     * @param ba the byte array to convert.
     * @return a string of hexadecimal characters (two for each byte)
     * representing the designated input byte array.
     */
    public static String toReversedString(byte[] ba) {
        return toReversedString(ba, 0, ba.length);
    }

    /**
     * <p>Returns a string of hexadecimal digits from a byte array, starting at
     * <code>offset</code> and consisting of <code>length</code> bytes. Each byte
     * is converted to 2 hex symbols; zero(es) included.</p>
     *
     * <p>The byte array is treated as a large little-endian integer, and
     * is returned as a large big-endian integer.</p>
     *
     * @param ba the byte array to convert.
     * @param offset the index from which to start considering the bytes to
     * convert.
     * @param length the count of bytes, starting from the designated offset to
     * convert.
     * @return a string of hexadecimal characters (two for each byte)
     * representing the designated input byte sub-array.
     */
    public static final String
    toReversedString(byte[] ba, int offset, int length) {
        char[] buf = new char[length * 2];
        for (int i = offset+length-1, j = 0, k; i >= offset; ) {
            k = ba[offset + i--];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
        }
        return new String(buf);
    }

    /**
     * <p>Returns a byte array from a string of hexadecimal digits.</p>
     *
     * @param s a string of hexadecimal ASCII characters
     * @return the decoded byte array from the input hexadecimal string.
     */
    public static byte[] toBytesFromString(String s) {
        int limit = s.length();
        byte[] result = new byte[((limit + 1) / 2)];
        int i = 0, j = 0;
        if ((limit % 2) == 1) {
            result[j++] = (byte) fromDigit(s.charAt(i++));
        }
        while (i < limit) {
            result[j  ]  = (byte) (fromDigit(s.charAt(i++)) << 4);
            result[j++] |= (byte)  fromDigit(s.charAt(i++));
        }
        return result;
    }

    /**
     * <p>Returns a byte array from a string of hexadecimal digits, interpreting
     * them as a large big-endian integer and returning it as a large
     * little-endian integer.</p>
     *
     * @param s a string of hexadecimal ASCII characters
     * @return the decoded byte array from the input hexadecimal string.
     */
    public static byte[] toReversedBytesFromString(String s) {
        int limit = s.length();
        byte[] result = new byte[((limit + 1) / 2)];
        int i = 0;
        if ((limit % 2) == 1) {
            result[i++] = (byte) fromDigit(s.charAt(--limit));
        }
        while (limit > 0) {
            result[i  ]  = (byte)  fromDigit(s.charAt(--limit));
            result[i++] |= (byte) (fromDigit(s.charAt(--limit)) << 4);
        }
        return result;
    }

    /**
     * <p>Returns a number from <code>0</code> to <code>15</code> corresponding
     * to the designated hexadecimal digit.</p>
     *
     * @param c a hexadecimal ASCII symbol.
     */
    public static int fromDigit(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        } else if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        } else if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        } else
            throw new IllegalArgumentException("Invalid hexadecimal digit: " + c);
    }

    /**
     * <p>Returns a string of 8 hexadecimal digits (most significant digit first)
     * corresponding to the unsigned integer <code>n</code>.</p>
     *
     * @param n the unsigned integer to convert.
     * @return a hexadecimal string 8-character long.
     */
    public static String toString(int n) {
        char[] buf = new char[8];
        for (int i = 7; i >= 0; i--) {
            buf[i] = HEX_DIGITS[n & 0x0F];
            n >>>= 4;
        }
        return new String(buf);
    }

    /**
     * <p>Returns a string of hexadecimal digits from an integer array. Each int
     * is converted to 4 hex symbols.</p>
     */
    public static String toString(int[] ia) {
        int length = ia.length;
        char[] buf = new char[length * 8];
        for (int i = 0, j = 0, k; i < length; i++) {
            k = ia[i];
            buf[j++] = HEX_DIGITS[(k >>> 28) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 24) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 20) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 16) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 12) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>>  8) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>>  4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k         & 0x0F];
        }
        return new String(buf);
    }

    /**
     * <p>Returns a string of 16 hexadecimal digits (most significant digit first)
     * corresponding to the unsigned long <code>n</code>.</p>
     *
     * @param n the unsigned long to convert.
     * @return a hexadecimal string 16-character long.
     */
    public static String toString(long n) {
        char[] b = new char[16];
        for (int i = 15; i >= 0; i--) {
            b[i] = HEX_DIGITS[(int)(n & 0x0FL)];
            n >>>= 4;
        }
        return new String(b);
    }

    /**
     * <p>Similar to the <code>toString()</code> method except that the Unicode
     * escape character is inserted before every pair of bytes. Useful to
     * externalise byte arrays that will be constructed later from such strings;
     * eg. s-box values.</p>
     *
     * @throws ArrayIndexOutOfBoundsException if the length is odd.
     */
    public static String toUnicodeString(byte[] ba) {
        return toUnicodeString(ba, 0, ba.length);
    }

    /**
     * <p>Similar to the <code>toString()</code> method except that the Unicode
     * escape character is inserted before every pair of bytes. Useful to
     * externalise byte arrays that will be constructed later from such strings;
     * eg. s-box values.</p>
     *
     * @throws ArrayIndexOutOfBoundsException if the length is odd.
     */
    public static final String
    toUnicodeString(byte[] ba, int offset, int length) {
        StringBuffer sb = new StringBuffer();
        int i = 0;
        int j = 0;
        int k;
        sb.append('\n').append("\"");
        while (i < length) {
            sb.append("\\u");

            k = ba[offset + i++];
            sb.append(HEX_DIGITS[(k >>> 4) & 0x0F]);
            sb.append(HEX_DIGITS[ k        & 0x0F]);

            k = ba[offset + i++];
            sb.append(HEX_DIGITS[(k >>> 4) & 0x0F]);
            sb.append(HEX_DIGITS[ k        & 0x0F]);

            if ((++j % 8) == 0) {
                sb.append("\"+").append('\n').append("\"");
            }
        }
        sb.append("\"").append('\n');
        return sb.toString();
    }

    /**
     * <p>Similar to the <code>toString()</code> method except that the Unicode
     * escape character is inserted before every pair of bytes. Useful to
     * externalise integer arrays that will be constructed later from such
     * strings; eg. s-box values.</p>
     *
     * @throws ArrayIndexOutOfBoundsException if the length is not a multiple of 4.
     */
    public static String toUnicodeString(int[] ia) {
        StringBuffer sb = new StringBuffer();
        int i = 0;
        int j = 0;
        int k;
        sb.append('\n').append("\"");
        while (i < ia.length) {
            k = ia[i++];
            sb.append("\\u");
            sb.append(HEX_DIGITS[(k >>> 28) & 0x0F]);
            sb.append(HEX_DIGITS[(k >>> 24) & 0x0F]);
            sb.append(HEX_DIGITS[(k >>> 20) & 0x0F]);
            sb.append(HEX_DIGITS[(k >>> 16) & 0x0F]);
            sb.append("\\u");
            sb.append(HEX_DIGITS[(k >>> 12) & 0x0F]);
            sb.append(HEX_DIGITS[(k >>>  8) & 0x0F]);
            sb.append(HEX_DIGITS[(k >>>  4) & 0x0F]);
            sb.append(HEX_DIGITS[ k         & 0x0F]);

            if ((++j % 4) == 0) {
                sb.append("\"+").append('\n').append("\"");
            }
        }
        sb.append("\"").append('\n');
        return sb.toString();
    }

    public static byte[] toBytesFromUnicode(String s) {
        int limit = s.length() * 2;
        byte[] result = new byte[limit];
        char c;
        for (int i = 0; i < limit; i++) {
            c = s.charAt(i >>> 1);
            result[i] = (byte)(((i & 1) == 0) ? c >>> 8 : c);
        }
        return result;
    }

    /**
     * <p>Dumps a byte array as a string, in a format that is easy to read for
     * debugging. The string <code>m</code> is prepended to the start of each
     * line.</p>
     *
     * <p>If <code>offset</code> and <code>length</code> are omitted, the whole
     * array is used. If <code>m</code> is omitted, nothing is prepended to each
     * line.</p>
     *
     * @param data the byte array to be dumped.
     * @param offset the offset within <i>data</i> to start from.
     * @param length the number of bytes to dump.
     * @param m a string to be prepended to each line.
     * @return a string containing the result.
     */
    public static String dumpString(byte[] data, int offset, int length, String m) {
        if (data == null) {
            return m + "null\n";
        }
        StringBuffer sb = new StringBuffer(length * 3);
        if (length > 32) {
            sb.append(m).append("Hexadecimal dump of ").append(length).append(" bytes...\n");
        }
        // each line will list 32 bytes in 4 groups of 8 each
        int end = offset + length;
        String s;
        int l = Integer.toString(length).length();
        if (l < 4) {
            l = 4;
        }
        for ( ; offset < end; offset += 32) {
            if (length > 32) {
                s = "         " + offset;
                sb.append(m).append(s.substring(s.length()-l)).append(": ");
            }
            int i = 0;
            for ( ; i < 32 && offset + i + 7 < end; i += 8) {
                sb.append(toString(data, offset + i, 8)).append(' ');
            }
            if (i < 32) {
                for ( ; i < 32 && offset + i < end; i++) {
                    sb.append(byteToString(data[offset + i]));
                }
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    public static String dumpString(byte[] data) {
        return (data == null) ? "null\n" : dumpString(data, 0, data.length, "");
    }

    public static String dumpString(byte[] data, String m) {
        return (data == null) ? "null\n" : dumpString(data, 0, data.length, m);
    }

    public static String dumpString(byte[] data, int offset, int length) {
        return dumpString(data, offset, length, "");
    }

    /**
     * <p>Returns a string of 2 hexadecimal digits (most significant digit first)
     * corresponding to the lowest 8 bits of <code>n</code>.</p>
     *
     * @param n the byte value to convert.
     * @return a string of 2 hex characters representing the input.
     */
    public static String byteToString(int n) {
        char[] buf = { HEX_DIGITS[(n >>> 4) & 0x0F], HEX_DIGITS[n & 0x0F] };
        return new String(buf);
    }

    /**
     * <p>Converts a designated byte array to a Base-64 representation, with the
     * exceptions that (a) leading 0-byte(s) are ignored, and (b) the character
     * '.' (dot) shall be used instead of "+' (plus).</p>
     *
     * <p>Used by SASL password file manipulation primitives.</p>
     *
     * @param buffer an arbitrary sequence of bytes to represent in Base-64.
     * @return unpadded (without the '=' character(s)) Base-64 representation of
     * the input.
     */
    public static final String toBase64(byte[] buffer) {
        int len = buffer.length, pos = len % 3;
        byte b0 = 0, b1 = 0, b2 = 0;
        switch (pos) {
            case 1:
                b2 = buffer[0];
                break;
            case 2:
                b1 = buffer[0];
                b2 = buffer[1];
                break;
        }
        StringBuffer sb = new StringBuffer();
        int c;
        boolean notleading = false;
        do {
            c = (b0 & 0xFC) >>> 2;
            if (notleading || c != 0) {
                sb.append(BASE64_CHARSET[c]);
                notleading = true;
            }
            c = ((b0 & 0x03) << 4) | ((b1 & 0xF0) >>> 4);
            if (notleading || c != 0) {
                sb.append(BASE64_CHARSET[c]);
                notleading = true;
            }
            c = ((b1 & 0x0F) << 2) | ((b2 & 0xC0) >>> 6);
            if (notleading || c != 0) {
                sb.append(BASE64_CHARSET[c]);
                notleading = true;
            }
            c = b2 & 0x3F;
            if (notleading || c != 0) {
                sb.append(BASE64_CHARSET[c]);
                notleading = true;
            }
            if (pos >= len) {
                break;
            } else {
                try {
                    b0 = buffer[pos++];
                    b1 = buffer[pos++];
                    b2 = buffer[pos++];
                } catch (ArrayIndexOutOfBoundsException x) {
                    break;
                }
            }
        } while (true);

        if (notleading) {
            return sb.toString();
        }
        return "0";
    }

    /**
     * <p>The inverse function of the above.</p>
     *
     * <p>Converts a string representing the encoding of some bytes in Base-64
     * to their original form.</p>
     *
     * @param str the Base-64 encoded representation of some byte(s).
     * @return the bytes represented by the <code>str</code>.
     * @throws NumberFormatException if <code>str</code> is <code>null</code>, or
     * <code>str</code> contains an illegal Base-64 character.
     * @see #toBase64(byte[])
     */
    public static final byte[] fromBase64(String str) {
        int len = str.length();
        if (len == 0) {
            throw new NumberFormatException("Empty string");
        }
        byte[] a = new byte[len + 1];
        int i, j;
        for (i = 0; i < len; i++) {
            try {
                a[i] = (byte) BASE64_CHARS.indexOf(str.charAt(i));
            } catch (ArrayIndexOutOfBoundsException x) {
                throw new NumberFormatException("Illegal character at #"+i);
            }
        }
        i = len - 1;
        j = len;
        try {
            while (true) {
                a[j] = a[i];
                if (--i < 0) {
                    break;
                }
                a[j] |= (a[i] & 0x03) << 6;
                j--;
                a[j] = (byte)((a[i] & 0x3C) >>> 2);
                if (--i < 0) {
                    break;
                }
                a[j] |= (a[i] & 0x0F) << 4;
                j--;
                a[j] = (byte)((a[i] & 0x30) >>> 4);
                if (--i < 0) {
                    break;
                }
                a[j] |= (a[i] << 2);
                j--;
                a[j] = 0;
                if (--i < 0) {
                    break;
                }
            }
        } catch (Exception ignored) {
        }

        try { // ignore leading 0-bytes
            while(a[j] == 0) {
                j++;
            }
        } catch (Exception x) {
            return new byte[1]; // one 0-byte
        }
        byte[] result = new byte[len - j + 1];
        System.arraycopy(a, j, result, 0, len - j + 1);
        return result;
    }

    // BigInteger utilities ----------------------------------------------------

    /**
     * <p>Treats the input as the MSB representation of a number, and discards
     * leading zero elements. For efficiency, the input is simply returned if no
     * leading zeroes are found.</p>
     *
     * @param n the {@link BigInteger} to trim.
     * @return the byte array representation of the designated {@link BigInteger}
     * with no leading 0-bytes.
     */
    public static final byte[] trim(BigInteger n) {
        byte[] in = n.toByteArray();
        if (in.length == 0 || in[0] != 0) {
            return in;
        }
        int len = in.length;
        int i = 1;
        while (in[i] == 0 && i < len) {
            ++i;
        }
        byte[] result = new byte[len - i];
        System.arraycopy(in, i, result, 0, len - i);
        return result;
    }

    /**
     * <p>Returns a hexadecimal dump of the trimmed bytes of a {@link BigInteger}.
     * </p>
     *
     * @param x the {@link BigInteger} to display.
     * @return the string representation of the designated {@link BigInteger}.
     */
    public static final String dump(BigInteger x) {
        return dumpString(trim(x));
    }
}

/**
 * <p>A basic abstract class to facilitate implementing symmetric key block
 * ciphers.</p>
 *
 * @version $Revision: 1.10 $
 */
abstract class BaseCipher implements IBlockCipher, IBlockCipherSpi {

    // Constants and variables
    // -------------------------------------------------------------------------

    /** The canonical name prefix of the cipher. */
    protected String name;

    /** The default block size, in bytes. */
    protected int defaultBlockSize;

    /** The default key size, in bytes. */
    protected int defaultKeySize;

    /** The current block size, in bytes. */
    protected int currentBlockSize;

    /** The session key for this instance. */
    protected transient Object currentKey;

    /** The instance lock. */
    protected Object lock = new Object();

    // Constructor(s)
    // -------------------------------------------------------------------------

    /**
     * <p>Trivial constructor for use by concrete subclasses.</p>
     *
     * @param name the canonical name prefix of this instance.
     * @param defaultBlockSize the default block size in bytes.
     * @param defaultKeySize the default key size in bytes.
     */
    protected BaseCipher(String name, int defaultBlockSize, int defaultKeySize) {
        super();

        this.name = name;
        this.defaultBlockSize = defaultBlockSize;
        this.defaultKeySize = defaultKeySize;
    }

    // Class methods
    // -------------------------------------------------------------------------

    // Instance methods
    // -------------------------------------------------------------------------

    // IBlockCipher interface implementation -----------------------------------

    public abstract Object clone();

    public String name() {
        StringBuffer sb = new StringBuffer(name).append('-');
        if (currentKey == null) {
            sb.append(String.valueOf(8*defaultBlockSize));
        } else {
            sb.append(String.valueOf(8*currentBlockSize));
        }
        return sb.toString();
    }

    public int defaultBlockSize() {
        return defaultBlockSize;
    }

    public int defaultKeySize() {
        return defaultKeySize;
    }

    public void init(Map attributes) throws InvalidKeyException {
        synchronized(lock) {
            if (currentKey != null) {
                throw new IllegalStateException();
            }

            Integer bs = (Integer) attributes.get(CIPHER_BLOCK_SIZE);
            if (bs == null) { // no block size was specified.
                if (currentBlockSize == 0) { // happy birthday
                    currentBlockSize = defaultBlockSize;
                } // else it's a clone. use as is
            } else {
                currentBlockSize = bs.intValue();
                // ensure that value is valid
                Iterator it;
                boolean ok = false;
                for (it = blockSizes(); it.hasNext(); ) {
                    ok = (currentBlockSize == ((Integer) it.next()).intValue());
                    if (ok) {
                        break;
                    }
                }
                if (!ok) {
                    throw new IllegalArgumentException(IBlockCipher.CIPHER_BLOCK_SIZE);
                }
            }

            byte[] k = (byte[]) attributes.get(KEY_MATERIAL);
            currentKey = makeKey(k, currentBlockSize);
        }
    }

    public int currentBlockSize() {
        if (currentKey == null) {
            throw new IllegalStateException();
        }
        return currentBlockSize;
    }

    public void reset() {
        synchronized(lock) {
//          currentBlockSize = 0;
            currentKey = null;
        }
    }

    public void encryptBlock(byte[] in, int inOffset, byte[] out, int outOffset)
            throws IllegalStateException {
        synchronized(lock) {
            if (currentKey == null) {
                throw new IllegalStateException();
            }

            encrypt(in, inOffset, out, outOffset, currentKey, currentBlockSize);
        }
    }

    public void decryptBlock(byte[] in, int inOffset, byte[] out, int outOffset)
            throws IllegalStateException {
        synchronized(lock) {
            if (currentKey == null) {
                throw new IllegalStateException();
            }

            decrypt(in, inOffset, out, outOffset, currentKey, currentBlockSize);
        }
    }

    public boolean selfTest() {
        int ks;
        Iterator bit;

        // do symmetry tests for all block-size/key-size combos
        for (Iterator kit = keySizes(); kit.hasNext(); ) {
            ks = ((Integer) kit.next()).intValue();
            for (bit = blockSizes(); bit.hasNext(); ) {
                if (!testSymmetry(ks, ((Integer) bit.next()).intValue())) {
                    return false;
                }
            }
        }

        return true;
    }

    // own methods -------------------------------------------------------------

    private boolean testSymmetry(int ks, int bs) {
        try {
            byte[] kb = new byte[ks];
            byte[] pt = new byte[bs];
            byte[] ct = new byte[bs];
            byte[] cpt = new byte[bs];
            int i;
            for (i = 0; i < ks; i++) {
                kb[i] = (byte) i;
            }
            for (i = 0; i < bs; i++) {
                pt[i] = (byte) i;
            }

            Object k = makeKey(kb, bs);
            encrypt(pt, 0, ct,  0, k, bs);
            decrypt(ct, 0, cpt, 0, k, bs);

            return Arrays.equals(pt, cpt);

        } catch (Exception x) {
            x.printStackTrace(System.err);
            return false;
        }
    }

    protected boolean testKat(byte[] kb, byte[] ct) {
        return testKat(kb, ct, new byte[ct.length]); // all-zero plaintext
    }

    protected boolean testKat(byte[] kb, byte[] ct, byte[] pt) {
        try {
            int bs = pt.length;
            byte[] t = new byte[bs];

            Object k = makeKey(kb, bs);

            // test encryption
            encrypt(pt, 0, t,  0, k, bs);
            if (!Arrays.equals(t, ct)) {
                return false;
            }
            // test decryption
            decrypt(t, 0, t, 0, k, bs);
            return Arrays.equals(t, pt);

        } catch (Exception x) {
            x.printStackTrace(System.err);
            return false;
        }
    }
}

/**
 * <p>Package-private interface exposing mandatory methods to be implemented by
 * concrete {@link gnu.crypto.cipher.BaseCipher} sub-classes.</p>
 *
 * @version $Revision: 1.4 $
 */
interface IBlockCipherSpi extends Cloneable {

    // Constants
    // -------------------------------------------------------------------------

    // Methods
    // -------------------------------------------------------------------------

    /**
     * <p>Returns an {@link java.util.Iterator} over the supported block sizes.
     * Each element returned by this object is a {@link java.lang.Integer}.</p>
     *
     * @return an <code>Iterator</code> over the supported block sizes.
     */
    Iterator blockSizes();

    /**
     * <p>Returns an {@link java.util.Iterator} over the supported key sizes.
     * Each element returned by this object is a {@link java.lang.Integer}.</p>
     *
     * @return an <code>Iterator</code> over the supported key sizes.
     */
    Iterator keySizes();

    /**
     * <p>Expands a user-supplied key material into a session key for a
     * designated <i>block size</i>.</p>
     *
     * @param k the user-supplied key material.
     * @param bs the desired block size in bytes.
     * @return an Object encapsulating the session key.
     * @exception IllegalArgumentException if the block size is invalid.
     * @exception InvalidKeyException if the key data is invalid.
     */
    Object makeKey(byte[]k, int bs) throws InvalidKeyException;

    /**
     * <p>Encrypts exactly one block of plaintext.</p>
     *
     * @param in the plaintext.
     * @param inOffset index of <code>in</code> from which to start considering
     * data.
     * @param out the ciphertext.
     * @param outOffset index of <code>out</code> from which to store the result.
     * @param k the session key to use.
     * @param bs the block size to use.
     * @exception IllegalArgumentException if the block size is invalid.
     * @exception ArrayIndexOutOfBoundsException if there is not enough room in
     * either the plaintext or ciphertext buffers.
     */
    void
    encrypt(byte[] in, int inOffset, byte[] out, int outOffset, Object k, int bs);

    /**
     * <p>Decrypts exactly one block of ciphertext.</p>
     *
     * @param in the ciphertext.
     * @param inOffset index of <code>in</code> from which to start considering
     * data.
     * @param out the plaintext.
     * @param outOffset index of <code>out</code> from which to store the result.
     * @param k the session key to use.
     * @param bs the block size to use.
     * @exception IllegalArgumentException if the block size is invalid.
     * @exception ArrayIndexOutOfBoundsException if there is not enough room in
     * either the plaintext or ciphertext buffers.
     */
    void
    decrypt(byte[] in, int inOffset, byte[] out, int outOffset, Object k, int bs);

    /**
     * <p>A <i>correctness</i> test that consists of basic symmetric encryption /
     * decryption test(s) for all supported block and key sizes, as well as one
     * (1) variable key Known Answer Test (KAT).</p>
     *
     * @return <code>true</code> if the implementation passes simple
     * <i>correctness</i> tests. Returns <code>false</code> otherwise.
     */
    boolean selfTest();
}

/**
 * <p>The basic visible methods of any symmetric key block cipher.</p>
 *
 * <p>A symmetric key block cipher is a function that maps n-bit plaintext
 * blocks to n-bit ciphertext blocks; n being the cipher's <i>block size</i>.
 * This encryption function is parameterised by a k-bit key, and is invertible.
 * Its inverse is the decryption function.</p>
 *
 * <p>Possible initialisation values for an instance of this type are:</p>
 *
 * <ul>
 *    <li>The block size in which to operate this block cipher instance. This
 *    value is <b>optional</b>, if unspecified, the block cipher's default
 *    block size shall be used.</li>
 *
 *    <li>The byte array containing the user supplied key material to use for
 *    generating the cipher's session key(s). This value is <b>mandatory</b>
 *    and should be included in the initialisation parameters. If it isn't,
 *    an {@link IllegalStateException} will be thrown if any method, other than
 *    <code>reset()</code> is invoked on the instance. Furthermore, the size of
 *    this key material shall be taken as an indication on the key size in which
 *    to operate this instance.</li>
 * </ul>
 *
 * <p><b>IMPLEMENTATION NOTE</b>: Although all the concrete classes in this
 * package implement the {@link Cloneable} interface, it is important to note
 * here that such an operation <b>DOES NOT</b> clone any session key material
 * that may have been used in initialising the source cipher (the instance to be
 * cloned). Instead a clone of an already initialised cipher is another instance
 * that operates with the <b>same block size</b> but without any knowledge of
 * neither key material nor key size.</p>
 *
 * @version $Revision: 1.7 $
 */
interface IBlockCipher extends Cloneable {

    // Constants
    // -------------------------------------------------------------------------

    /**
     * <p>Property name of the block size in which to operate a block cipher.
     * The value associated with this property name is taken to be an
     * {@link Integer}.</p>
     */
    String CIPHER_BLOCK_SIZE = "gnu.crypto.cipher.block.size";

    /**
     * <p>Property name of the user-supplied key material. The value associated
     * to this property name is taken to be a byte array.</p>
     */
    String KEY_MATERIAL = "gnu.crypto.cipher.key.material";

    // Methods
    // -------------------------------------------------------------------------

    /**
     * <p>Returns the canonical name of this instance.</p>
     *
     * @return the canonical name of this instance.
     */
    String name();

    /**
     * <p>Returns the default value, in bytes, of the algorithm's block size.</p>
     *
     * @return the default value, in bytes, of the algorithm's block size.
     */
    int defaultBlockSize();

    /**
     * <p>Returns the default value, in bytes, of the algorithm's key size.</p>
     *
     * @return the default value, in bytes, of the algorithm's key size.
     */
    int defaultKeySize();

    /**
     * <p>Returns an {@link Iterator} over the supported block sizes. Each
     * element returned by this object is an {@link Integer}.</p>
     *
     * @return an {@link Iterator} over the supported block sizes.
     */
    Iterator blockSizes();

    /**
     * <p>Returns an {@link Iterator} over the supported key sizes. Each element
     * returned by this object is an {@link Integer}.</p>
     *
     * @return an {@link Iterator} over the supported key sizes.
     */
    Iterator keySizes();

    /**
     * <p>Returns a clone of this instance.</p>
     *
     * @return a clone copy of this instance.
     */
    Object clone();

    /**
     * <p>Initialises the algorithm with designated attributes. Permissible names
     * and values are described in the class documentation above.</p>
     *
     * @param attributes a set of name-value pairs that describes the desired
     * future behaviour of this instance.
     * @exception InvalidKeyException if the key data is invalid.
     * @exception IllegalStateException if the instance is already initialised.
     * @see #KEY_MATERIAL
     * @see #CIPHER_BLOCK_SIZE
     */
    void init(Map attributes)
            throws InvalidKeyException, IllegalStateException;

    /**
     * <p>Returns the currently set block size for this instance.</p>
     *
     * @return the current block size for this instance.
     * @exception IllegalStateException if the instance is not initialised.
     */
    int currentBlockSize() throws IllegalStateException;

    /**
     * <p>Resets the algorithm instance for re-initialisation and use with other
     * characteristics. This method always succeeds.</p>
     */
    void reset();

    /**
     * <p>Encrypts exactly one block of plaintext.</p>
     *
     * @param in the plaintext.
     * @param inOffset index of <code>in</code> from which to start considering
     * data.
     * @param out the ciphertext.
     * @param outOffset index of <code>out</code> from which to store result.
     * @exception IllegalStateException if the instance is not initialised.
     */
    void encryptBlock(byte[] in, int inOffset, byte[] out, int outOffset)
            throws IllegalStateException;

    /**
     * <p>Decrypts exactly one block of ciphertext.</p>
     *
     * @param in the plaintext.
     * @param inOffset index of <code>in</code> from which to start considering
     * data.
     * @param out the ciphertext.
     * @param outOffset index of <code>out</code> from which to store result.
     * @exception IllegalStateException if the instance is not initialised.
     */
    void decryptBlock(byte[] in, int inOffset, byte[] out, int outOffset)
            throws IllegalStateException;

    /**
     * <p>A <i>correctness</i> test that consists of basic symmetric encryption /
     * decryption test(s) for all supported block and key sizes, as well as one
     * (1) variable key Known Answer Test (KAT).</p>
     *
     * @return <code>true</code> if the implementation passes simple
     * <i>correctness</i> tests. Returns <code>false</code> otherwise.
     */
    boolean selfTest();
}
