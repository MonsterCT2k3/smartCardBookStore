package crypto;

import javacard.framework.*;
import javacard.security.*;

public class Pbkdf2HmacSha256 {

    // Kich thuoc Block cua SHA-256 la 64 bytes
    private static final byte BLOCK_SIZE = 64;
    // Kich thuoc Output cua SHA-256 la 32 bytes
    private static final byte HASH_SIZE = 32;

    private MessageDigest sha256;

    // Cac bo nho dem (RAM) de tinh toan
    private byte[] k_ipad; // Key XOR ipad
    private byte[] k_opad; // Key XOR opad
    private byte[] u_last; // Ket qua vong lap truoc (U_i-1)
    private byte[] u_xor; // Ket qua tich luy (F = U1 ^ U2 ^ ...)
    private byte[] scratch; // Buffer tam

    public Pbkdf2HmacSha256() {
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        // Cap phat bo nho RAM (Transient) de chay nhanh va khong hai the
        k_ipad = JCSystem.makeTransientByteArray(BLOCK_SIZE, JCSystem.CLEAR_ON_RESET);
        k_opad = JCSystem.makeTransientByteArray(BLOCK_SIZE, JCSystem.CLEAR_ON_RESET);
        u_last = JCSystem.makeTransientByteArray(HASH_SIZE, JCSystem.CLEAR_ON_RESET);
        u_xor = JCSystem.makeTransientByteArray(HASH_SIZE, JCSystem.CLEAR_ON_RESET);
        scratch = JCSystem.makeTransientByteArray(BLOCK_SIZE, JCSystem.CLEAR_ON_RESET);
    }

    /**
     * Ham chinh: Dan xuat khoa
     * 
     * @param pin:        Mat khau (PIN)
     * @param salt:       Muoi
     * @param iterations: So lan lap (Vi du: 1000)
     * @param outKey:     Mang chua key ket qua
     * @param outOff:     Vi tri bat dau ghi key
     */
    public void derive(byte[] pin, short pinOff, short pinLen,
            byte[] salt, short saltOff, short saltLen,
            short iterations,
            byte[] outKey, short outOff) {

        // --- Giai doan 1: Chuan bi HMAC Key (Pad PIN) ---
        // Xoa sach buffer cu
        Util.arrayFillNonAtomic(k_ipad, (short) 0, BLOCK_SIZE, (byte) 0x36);
        Util.arrayFillNonAtomic(k_opad, (short) 0, BLOCK_SIZE, (byte) 0x5C);

        // Neu PIN dai hon 64 bytes (hiem), can hash PIN truoc (nhung PIN nha sach ngan
        // nen bo qua logic do cho nhe)
        // XOR PIN voi 0x36 (ipad) va 0x5C (opad)
        for (short i = 0; i < pinLen; i++) {
            byte p = pin[(short) (pinOff + i)];
            k_ipad[i] ^= p;
            k_opad[i] ^= p;
        }

        // --- Giai doan 2: Tinh U1 = HMAC(Salt || INT(1)) ---
        // HMAC Part 1: Hash(k_ipad || Salt || 00 00 00 01)
        sha256.reset();
        sha256.update(k_ipad, (short) 0, BLOCK_SIZE);
        sha256.update(salt, saltOff, saltLen);
        // Append INT(1) - Block index dau tien (4 bytes: 00 00 00 01)
        scratch[0] = 0;
        scratch[1] = 0;
        scratch[2] = 0;
        scratch[3] = 1;
        sha256.doFinal(scratch, (short) 0, (short) 4, u_last, (short) 0); // Ket qua tam vao u_last

        // HMAC Part 2: Hash(k_opad || Result_Part1)
        sha256.reset();
        sha256.update(k_opad, (short) 0, BLOCK_SIZE);
        sha256.doFinal(u_last, (short) 0, HASH_SIZE, u_last, (short) 0); // U1 hoan chinh nam trong u_last

        // Copy U1 vao u_xor (Khoi tao gia tri ban dau cho F)
        Util.arrayCopyNonAtomic(u_last, (short) 0, u_xor, (short) 0, HASH_SIZE);

        // --- Giai doan 3: Vong lap U2...Un (PBKDF2 loop) ---
        // Chay tu 2 den iterations
        for (short i = 1; i < iterations; i++) {
            // Tinh U_i = HMAC(U_{i-1})

            // Hash(k_ipad || U_last)
            sha256.reset();
            sha256.update(k_ipad, (short) 0, BLOCK_SIZE);
            sha256.doFinal(u_last, (short) 0, HASH_SIZE, scratch, (short) 0); // Tam luu vao scratch

            // Hash(k_opad || scratch)
            sha256.reset();
            sha256.update(k_opad, (short) 0, BLOCK_SIZE);
            sha256.doFinal(scratch, (short) 0, HASH_SIZE, u_last, (short) 0); // U_i moi nam trong u_last

            // XOR dan vao ket qua: F = F ^ U_i
            for (short j = 0; j < HASH_SIZE; j++) {
                u_xor[j] ^= u_last[j];
            }
        }

        // --- Giai doan 4: Tra ket qua ---
        // Copy 16 bytes dau tien (128 bit) lam AES Key
        Util.arrayCopyNonAtomic(u_xor, (short) 0, outKey, outOff, (short) 16);
    }
}
