
import java.util.Arrays;

public class DES implements Algorithm {
    private final byte[] key8;

    public DES(byte[] key) {
        key8 = new byte[8];
        if (key != null) {
            for (int i = 0; i < Math.min(8, key.length); i++)
                key8[i] = key[i];
        }
    }

    @Override
    public byte[] Encrypt(byte[] plain) {
        if (plain == null)
            return new byte[0];
        byte[] padded = pkcs5Pad(plain);
        byte[] out = new byte[padded.length];
        int[][] subkeys = generateSubkeys(key8);
        for (int i = 0; i < padded.length; i += 8) {
            long block = bytesToLong(Arrays.copyOfRange(padded, i, i + 8));
            long enc = encryptBlock(block, subkeys);
            longToBytes(enc, out, i);
        }
        return out;
    }

    @Override
    public byte[] Decrypt(byte[] cipher) {
        if (cipher == null || cipher.length % 8 != 0)
            return new byte[0];
        byte[] out = new byte[cipher.length];
        int[][] subkeys = generateSubkeys(key8);

        for (int i = 0; i < cipher.length; i += 8) {
            long block = bytesToLong(Arrays.copyOfRange(cipher, i, i + 8));
            long dec = decryptBlock(block, subkeys);
            longToBytes(dec, out, i);
        }
        return pkcs5Unpad(out);
    }

    // --- DES core ---

    private static final int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    private static final int[] FP = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
    };

    private static final int[] E = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
    };

    private static final int[][][] S = {
            {
                    { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                    { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                    { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                    { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
            },
            {
                    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                    { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                    { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                    { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
            },
            {
                    { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                    { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                    { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                    { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
            },
            {
                    { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                    { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                    { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                    { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
            },
            {
                    { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                    { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                    { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                    { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
            },
            {
                    { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                    { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                    { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                    { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
            },
            {
                    { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                    { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                    { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                    { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
            },
            {
                    { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                    { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                    { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                    { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
            }
    };

    private static final int[] P = {
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
    };

    private static final int[] PC1 = {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
    };

    private static final int[] PC2 = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
    };

    private static final int[] SHIFTS = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

    private static long encryptBlock(long block, int[][] subkeys) {
        long ip = permute64(block, IP);
        int L = (int) (ip >>> 32);
        int R = (int) (ip & 0xFFFFFFFFL);
        for (int round = 0; round < 16; round++) {
            int f = feistel(R, subkeys[round]);
            int newL = R;
            int newR = L ^ f;
            L = newL;
            R = newR;
        }
        long preoutput = ((long) R & 0xFFFFFFFFL) << 32 | ((long) L & 0xFFFFFFFFL);
        return permute64(preoutput, FP);
    }

    private static long decryptBlock(long block, int[][] subkeys) {
        long ip = permute64(block, IP);
        int L = (int) (ip >>> 32);
        int R = (int) (ip & 0xFFFFFFFFL);
        for (int r = 15; r >= 0; r--) {
            int f = feistel(R, subkeys[r]);
            int newL = R;
            int newR = L ^ f;
            L = newL;
            R = newR;
        }
        long preoutput = ((long) R & 0xFFFFFFFFL) << 32 | ((long) L & 0xFFFFFFFFL);
        return permute64(preoutput, FP);
    }

    private static int feistel(int R, int[] subkey48) {
        long expanded = permute32To48(R, E);
        long x = expanded ^ bits48ToLong(subkey48);
        int out32 = sboxP(x);
        return out32;
    }

    private static int sboxP(long x48) {
        int out = 0;
        for (int i = 0; i < 8; i++) {
            int sixBits = (int) ((x48 >>> (42 - 6 * i)) & 0x3F);
            int row = ((sixBits & 0x20) >>> 4) | (sixBits & 0x1);
            int col = (sixBits >>> 1) & 0xF;
            int val = S[i][row][col];
            out = (out << 4) | val;
        }

        return (int) permute32(out, P);
    }

    private static int[][] generateSubkeys(byte[] key8) {
        long key64 = bytesToLong(key8);
        // drop parity bits via PC1 -> 56 bits
        long key56 = permute64To56(key64, PC1);
        int C = (int) ((key56 >>> 28) & 0x0FFFFFFF);
        int D = (int) (key56 & 0x0FFFFFFF);
        int[][] subkeys = new int[16][48];
        for (int r = 0; r < 16; r++) {
            C = leftRotate28(C, SHIFTS[r]);
            D = leftRotate28(D, SHIFTS[r]);
            long CD = (((long) C & 0x0FFFFFFFL) << 28) | ((long) D & 0x0FFFFFFFL);
            long k48 = permute56To48(CD, PC2);

            for (int i = 0; i < 48; i++) {
                subkeys[r][i] = (int) ((k48 >>> (47 - i)) & 1L);
            }
        }
        return subkeys;
    }

    // --- bit helpers ---

    private static long permute64(long x, int[] table) {
        long out = 0L;
        for (int i = 0; i < table.length; i++) {
            int src = 64 - table[i];
            out = (out << 1) | ((x >>> src) & 1L);
        }
        return out;
    }

    private static long permute64To56(long x, int[] table) {
        long out = 0L;
        for (int i = 0; i < table.length; i++) {
            int src = 64 - table[i];
            out = (out << 1) | ((x >>> src) & 1L);
        }
        return out; // 56-bit value in low bits
    }

    private static long permute56To48(long x, int[] table) {
        long out = 0L;
        for (int i = 0; i < table.length; i++) {
            int src = 56 - table[i];
            out = (out << 1) | ((x >>> src) & 1L);
        }
        return out;
    }

    private static long permute32(long x, int[] table) {
        long out = 0L;
        for (int i = 0; i < table.length; i++) {
            int src = 32 - table[i];
            out = (out << 1) | ((x >>> src) & 1L);
        }
        return out & 0xFFFFFFFFL;
    }

    private static long permute32To48(int x, int[] table) {
        long out = 0L;
        long xl = x & 0xFFFFFFFFL;
        for (int i = 0; i < table.length; i++) {
            int src = 32 - table[i];
            out = (out << 1) | ((xl >>> src) & 1L);
        }
        return out;
    }

    private static long bits48ToLong(int[] bits) {
        long v = 0L;
        for (int i = 0; i < 48; i++) {
            v = (v << 1) | (bits[i] & 1L);
        }
        return v;
    }

    private static int leftRotate28(int v, int n) {
        v &= 0x0FFFFFFF;
        return ((v << n) | (v >>> (28 - n))) & 0x0FFFFFFF;
    }

    private static byte[] pkcs5Pad(byte[] in) {
        int pad = 8 - (in.length % 8);
        if (pad == 0)
            pad = 8;
        byte[] out = Arrays.copyOf(in, in.length + pad);
        for (int i = in.length; i < out.length; i++)
            out[i] = (byte) pad;
        return out;
    }

    private static byte[] pkcs5Unpad(byte[] in) {
        if (in.length == 0)
            return in;
        int pad = in[in.length - 1] & 0xFF;
        if (pad <= 0 || pad > 8)
            return in;
        for (int i = in.length - pad; i < in.length; i++) {
            if ((in[i] & 0xFF) != pad)
                return in; // invalid padding, return raw
        }
        return Arrays.copyOf(in, in.length - pad);
    }

    private static long bytesToLong(byte[] b8) {
        long v = 0L;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (b8[i] & 0xFFL);
        }
        return v;
    }

    private static void longToBytes(long v, byte[] out, int offset) {
        for (int i = 7; i >= 0; i--) {
            out[offset + (7 - i)] = (byte) ((v >>> (i * 8)) & 0xFF);
        }
    }
}
