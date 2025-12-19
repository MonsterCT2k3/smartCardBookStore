package crypto;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import common.Constants;

public class SecurityManager {

    // --- CAC DOI TUONG KEY ---
    private AESKey masterKey; // Khoa chu (AES-128) - Dung de encrypt du lieu User
    private AESKey tempKey; // Khoa tam (AES-128) - Dung cho PBKDF2 hoac thao tac tam

    // --- THAY DOI: KHONG LUU KEYPAIR VINH VIEN ---
    // private KeyPair cardRsaKeyPair; // REMOVED

    // Luu tru Private Key da ma hoa (128 bytes - chi chua Exponent)
    private byte[] encryptedPrivateKey;

    // Public Key (Luu trong EEPROM de chia se cho App)
    private RSAPublicKey publicKey;

    // Private Key Tam (Chi chua data khi can dung, xoa ngay sau do)
    private RSAPrivateKey transientPrivateKey;

    private RSAPublicKey appPublicKey; // Khoa Public cua App (Desktop) gui xuong

    // --- LUU TRU TRONG EEPROM ---
    private byte[] encryptedMasterKey; // MasterKey bi ma hoa boi PIN
    private byte[] masterKeyHash; // Hash cua MasterKey (de kiem tra dung sai)
    private byte[] cardSalt; // Muoi (Salt) dung cho PBKDF2

    // Admin Key (de reset User Key khi quen PIN)
    private byte[] encryptedAdminKey; // AdminKey bi ma hoa boi AdminPIN
    private byte[] encryptedMasterKeyByAdmin; // MasterKey bi ma hoa boi AdminKey (Backup)
    private byte[] adminKeyHash; // Hash cua AdminKey (de kiem tra dung sai)
    private byte[] adminSalt; // Muoi (Salt) rieng cho Admin

    // --- CONG CU TINH TOAN (ENGINES) ---
    private Pbkdf2HmacSha256 pbkdf2;
    private MessageDigest sha256;
    private Cipher aesCipher; // AES CBC NOPAD
    private Cipher rsaCipher; // RSA PKCS1
    private Signature rsaSignature; // Chu ky so
    private RandomData random; // Sinh so ngau nhien

    // --- BO NHO DEM (RAM) ---
    private byte[] scratch; // Buffer da dung (phai du lon ~256 bytes cho RSA Key components)
    private byte[] zeroIV; // IV toan 0 de reset trang thai Cipher

    // --- TRANG THAI ---
    private boolean isUnlocked;
    private byte pinTries;
    private boolean isSetup; // Check if setupCard has been called

    public SecurityManager() {
        // 1. Khoi tao cac Key rong
        masterKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        tempKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        // 2. Init Storage cho Keys
        // Public Key (Persistent)
        publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);

        // Private Key (Transient Container - Persistent Object but treated as
        // transient)
        // Note: Creating a persistent key object but we will manage its content
        transientPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
                KeyBuilder.LENGTH_RSA_1024, false);

        // Encrypted Private Key Blob (128 bytes Exponent)
        encryptedPrivateKey = new byte[128]; // RSA 1024 bit exponent length

        // Tao object chua Key cua App
        appPublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024,
                false);

        // 3. Cap phat bo nho luu tru EEPROM
        encryptedMasterKey = new byte[16];
        masterKeyHash = new byte[32];
        cardSalt = new byte[16];

        encryptedAdminKey = new byte[16];
        encryptedMasterKeyByAdmin = new byte[16];
        adminKeyHash = new byte[32];
        adminSalt = new byte[16];

        // 4. Khoi tao Engines
        pbkdf2 = new Pbkdf2HmacSha256();
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        rsaSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        // Buffer tam trong RAM (Transient)
        // Tang size len 256 de chua Modulus/Exponent khi thao tac
        scratch = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
        // IV toan 0 (Transient)
        zeroIV = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);

        isUnlocked = false;
        pinTries = 0;
        isSetup = false;
    }

    // =========================================================================
    // HELPER: ENCRYPT / RESTORE PRIVATE KEY
    // =========================================================================

    // Encrypt Private Key (Exponent) using MasterKey (Plain) and store to EEPROM
    // MasterKey must be present in masterKeyBuffer (scratch)
    private void encryptAndStorePrivateKey(RSAPrivateKey privKey, byte[] masterKeyBuffer, short masterKeyOff) {
        // 1. Extract Private Exponent -> scratch[160] (Tranh vung MasterKey o
        // scratch[0..31])
        // Exponent RSA 1024 = 128 bytes. Use buffer at 128.
        short expLen = privKey.getExponent(scratch, (short) 128);

        // Fix: Ensure exactly 128 bytes for AES CBC NOPAD
        // If expLen < 128, pad with leading zeros (Right Align)
        if (expLen < 128) {
            short diff = (short) (128 - expLen);
            // Move data to end
            Util.arrayCopyNonAtomic(scratch, (short) 128, scratch, (short) (128 + diff), expLen);
            // Fill leading with 0
            Util.arrayFillNonAtomic(scratch, (short) 128, diff, (byte) 0);
        }

        // 2. Encrypt Exponent using Master Key
        // Load Master Key to tempKey for encryption
        tempKey.setKey(masterKeyBuffer, masterKeyOff);

        aesCipher.init(tempKey, Cipher.MODE_ENCRYPT, zeroIV, (short) 0, (short) 16);

        // Always encrypt 128 bytes
        aesCipher.doFinal(scratch, (short) 128, (short) 128, encryptedPrivateKey, (short) 0);

        // Clean scratch
        Util.arrayFillNonAtomic(scratch, (short) 128, (short) 128, (byte) 0);
    }

    // Restore Private Key from EEPROM -> transientPrivateKey
    // Require: isUnlocked = true (MasterKey loaded)
    private void restorePrivateKey() {
        if (!isUnlocked) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // 1. Decrypt EncryptedPrivateKey -> scratch
        aesCipher.init(masterKey, Cipher.MODE_DECRYPT, zeroIV, (short) 0, (short) 16);
        aesCipher.doFinal(encryptedPrivateKey, (short) 0, (short) 128, scratch, (short) 0);

        // 2. Set Exponent to transientPrivateKey
        transientPrivateKey.setExponent(scratch, (short) 0, (short) 128);

        // 3. Set Modulus to transientPrivateKey (Lay tu PublicKey)
        // Can Modulus de RSA hoat dong
        short modLen = publicKey.getModulus(scratch, (short) 0);
        transientPrivateKey.setModulus(scratch, (short) 0, modLen);

        // Clean scratch (Sensitive Exponent)
        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 128, (byte) 0);
    }

    private void clearTransientPrivateKey() {
        transientPrivateKey.clearKey();
    }

    // =========================================================================
    // PHAN 1: QUAN LY SETUP & PIN
    // =========================================================================

    private boolean checkAdminPin(byte[] pinBuffer, short pinOffset) {
        // Derive AdminPIN -> Key thu (scratch[64])
        pbkdf2.derive(pinBuffer, pinOffset, (short) 6, adminSalt, (short) 0, (short) 16, Constants.PBKDF2_ITERATIONS,
                scratch, (short) 64);
        tempKey.setKey(scratch, (short) 64);

        // Giai ma encryptedAdminKey -> scratch[80]
        aesCipher.init(tempKey, Cipher.MODE_DECRYPT, zeroIV, (short) 0, (short) 16);
        aesCipher.doFinal(encryptedAdminKey, (short) 0, (short) 16, scratch, (short) 80);

        // Hash -> scratch[96]
        sha256.reset();
        sha256.doFinal(scratch, (short) 80, (short) 16, scratch, (short) 96);

        return Util.arrayCompare(scratch, (short) 96, adminKeyHash, (short) 0, (short) 32) == 0;
    }

    public void processUnblockCard(byte[] buffer, short offset, short len) {
        if (len < 6)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        if (checkAdminPin(buffer, offset)) {
            pinTries = 0;
        } else {
            ISOException.throwIt(Constants.SW_VERIFICATION_FAILED);
        }
    }

    public short decryptIncomingData(byte[] buffer, short offset, short len) {
        // --- MODIFIED: DECRYPT ON DEMAND ---
        restorePrivateKey();

        try {
            // 1. Init RSA with Decrypt Mode
            rsaCipher.init(transientPrivateKey, Cipher.MODE_DECRYPT);

            // Giai ma Session Key -> scratch[0..15]
            rsaCipher.doFinal(buffer, offset, (short) 128, scratch, (short) 0);

            // 2. Load Session Key vao TempKey
            tempKey.setKey(scratch, (short) 0);

            // 3. Giai ma Data AES
            short dataOff = (short) (offset + 128);
            short dataLen = (short) (len - 128);

            aesCipher.init(tempKey, Cipher.MODE_DECRYPT, zeroIV, (short) 0, (short) 16);
            short plainLen = aesCipher.doFinal(buffer, dataOff, dataLen, buffer, offset);

            // Cleanup
            Util.arrayFillNonAtomic(scratch, (short) 0, (short) 16, (byte) 0);

            return plainLen;
        } finally {
            clearTransientPrivateKey();
        }
    }

    public void setupCard(byte[] buffer, short offset, short len) {
        if (len != 12)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short userPinOff = offset;
        short adminPinOff = (short) (offset + 6);

        JCSystem.beginTransaction();
        try {
            // --- XU LY USER KEY ---
            // 1. Sinh User MasterKey ngau nhien -> scratch[16..31]
            random.generateData(scratch, (short) 16, (short) 16);

            // --- NEW: GEN RSA KEYPAIR & ENCRYPT WITH MASTER KEY ---
            // Tao KeyPair tam
            KeyPair tempPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            tempPair.genKeyPair();

            // Encrypt & Store Private Key (Dung MasterKey o scratch[16])
            encryptAndStorePrivateKey((RSAPrivateKey) tempPair.getPrivate(), scratch, (short) 16);

            // Store Public Key
            RSAPublicKey tempPub = (RSAPublicKey) tempPair.getPublic();
            short rsaLen = tempPub.getModulus(scratch, (short) 128); // Muon tmp buffer
            publicKey.setModulus(scratch, (short) 128, rsaLen);
            rsaLen = tempPub.getExponent(scratch, (short) 128);
            publicKey.setExponent(scratch, (short) 128, rsaLen);
            // ----------------------------------------------------

            // 2. Tao Salt ngau nhien cho User
            random.generateData(cardSalt, (short) 0, (short) 16);

            // 3. Dan xuat UserPIN -> TempKey (scratch[0..15])
            pbkdf2.derive(buffer, userPinOff, (short) 6, cardSalt, (short) 0, (short) 16, Constants.PBKDF2_ITERATIONS,
                    scratch, (short) 0);
            tempKey.setKey(scratch, (short) 0);

            // 4. Ma hoa User MasterKey (dang o scratch[16]) bang TempKey ->
            // encryptedMasterKey
            aesCipher.init(tempKey, Cipher.MODE_ENCRYPT, zeroIV, (short) 0, (short) 16);
            aesCipher.doFinal(scratch, (short) 16, (short) 16, encryptedMasterKey, (short) 0);

            // 5. Hash User MasterKey
            sha256.reset();
            sha256.doFinal(scratch, (short) 16, (short) 16, masterKeyHash, (short) 0);

            // --- XU LY ADMIN KEY ---
            // 6. Sinh Admin Key ngau nhien -> scratch[32..47]
            random.generateData(scratch, (short) 32, (short) 16);

            // 7. Tao Salt Admin
            random.generateData(adminSalt, (short) 0, (short) 16);

            // 8. Dan xuat AdminPIN -> TempKey (reuse) -> scratch[64..79]
            pbkdf2.derive(buffer, adminPinOff, (short) 6, adminSalt, (short) 0, (short) 16, Constants.PBKDF2_ITERATIONS,
                    scratch, (short) 64);
            tempKey.setKey(scratch, (short) 64);

            // 9. Ma hoa AdminKey (scratch[32]) -> encryptedAdminKey
            aesCipher.init(tempKey, Cipher.MODE_ENCRYPT, zeroIV, (short) 0, (short) 16);
            aesCipher.doFinal(scratch, (short) 32, (short) 16, encryptedAdminKey, (short) 0);

            // 10. Hash AdminKey
            sha256.reset();
            sha256.doFinal(scratch, (short) 32, (short) 16, adminKeyHash, (short) 0);

            // 11. Backup MasterKey (scratch[16]) bang AdminKey (scratch[32])
            tempKey.setKey(scratch, (short) 32);
            aesCipher.init(tempKey, Cipher.MODE_ENCRYPT, zeroIV, (short) 0, (short) 16);
            aesCipher.doFinal(scratch, (short) 16, (short) 16, encryptedMasterKeyByAdmin, (short) 0);

            isSetup = true;
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 256, (byte) 0);
    }

    public void processResetUserKey(byte[] buffer, short offset, short len) {
        if (len < 12)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        resetUserKey(buffer, offset);
    }

    public void resetUserKey(byte[] buffer, short offset) {
        short adminPinOff = offset;
        short newUserPinOff = (short) (offset + 6);

        if (!checkAdminPin(buffer, adminPinOff)) {
            ISOException.throwIt(Constants.SW_VERIFICATION_FAILED);
        }

        // AdminKey Plain dang o scratch[80..95]
        JCSystem.beginTransaction();
        try {
            // 1. Khoi phuc MasterKey cu -> scratch[16..31]
            tempKey.setKey(scratch, (short) 80);
            aesCipher.init(tempKey, Cipher.MODE_DECRYPT, zeroIV, (short) 0, (short) 16);
            aesCipher.doFinal(encryptedMasterKeyByAdmin, (short) 0, (short) 16, scratch, (short) 16);

            // --- Key Rotation ---
            KeyPair tempPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            tempPair.genKeyPair();

            // Encrypt Private Key with Recovered MasterKey (scratch[16])
            encryptAndStorePrivateKey((RSAPrivateKey) tempPair.getPrivate(), scratch, (short) 16);

            // Store Public Key
            RSAPublicKey tempPub = (RSAPublicKey) tempPair.getPublic();
            short rsaLen = tempPub.getModulus(scratch, (short) 128);
            publicKey.setModulus(scratch, (short) 128, rsaLen);
            rsaLen = tempPub.getExponent(scratch, (short) 128);
            publicKey.setExponent(scratch, (short) 128, rsaLen);
            // ---------------------

            // 2. Dan xuat NewUserPIN -> TempKey
            pbkdf2.derive(buffer, newUserPinOff, (short) 6, cardSalt, (short) 0, (short) 16,
                    Constants.PBKDF2_ITERATIONS, scratch, (short) 64);
            tempKey.setKey(scratch, (short) 64);

            // 3. Ma hoa lai MasterKey
            aesCipher.init(tempKey, Cipher.MODE_ENCRYPT, zeroIV, (short) 0, (short) 16);
            aesCipher.doFinal(scratch, (short) 16, (short) 16, encryptedMasterKey, (short) 0);

            // 4. Hash (Optional)
            sha256.reset();
            sha256.doFinal(scratch, (short) 16, (short) 16, masterKeyHash, (short) 0);

            pinTries = 0;
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 256, (byte) 0);
    }

    public void verifyPin(byte[] buffer, short offset, short len) {
        if (pinTries >= Constants.PIN_MAX_TRIES)
            ISOException.throwIt(Constants.SW_CARD_LOCKED);
        if (len < 6)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        verifyPinInternal(buffer, offset, (short) 6);
    }

    private void verifyPinInternal(byte[] pin, short pinOff, short pinLen) {
        // 1. PIN -> TempKey (scratch[64])
        pbkdf2.derive(pin, pinOff, pinLen, cardSalt, (short) 0, (short) 16, Constants.PBKDF2_ITERATIONS, scratch,
                (short) 64);
        tempKey.setKey(scratch, (short) 64);

        // 2. Decrypt MasterKey -> scratch[80]
        aesCipher.init(tempKey, Cipher.MODE_DECRYPT, zeroIV, (short) 0, (short) 16);
        aesCipher.doFinal(encryptedMasterKey, (short) 0, (short) 16, scratch, (short) 80);

        // 3. Validate Hash
        sha256.reset();
        sha256.doFinal(scratch, (short) 80, (short) 16, scratch, (short) 96);

        if (Util.arrayCompare(scratch, (short) 96, masterKeyHash, (short) 0, (short) 32) == 0) {
            pinTries = 0;
            isUnlocked = true;
            masterKey.setKey(scratch, (short) 80);
        } else {
            pinTries++;
            isUnlocked = false;
            ISOException.throwIt(Constants.SW_VERIFICATION_FAILED);
        }
        Util.arrayFillNonAtomic(scratch, (short) 64, (short) 64, (byte) 0);
    }

    public void changePin(byte[] buffer, short offset, short len) {
        if (len < 12)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        changePinInternal(buffer, offset);
    }

    private void changePinInternal(byte[] buffer, short offset) {
        short oldPinOff = offset;
        short newPinOff = (short) (offset + 6);

        // Verify Old PIN & Get MasterKey (scratch[16])
        pbkdf2.derive(buffer, oldPinOff, (short) 6, cardSalt, (short) 0, (short) 16, Constants.PBKDF2_ITERATIONS,
                scratch, (short) 64);
        tempKey.setKey(scratch, (short) 64);
        aesCipher.init(tempKey, Cipher.MODE_DECRYPT, zeroIV, (short) 0, (short) 16);
        aesCipher.doFinal(encryptedMasterKey, (short) 0, (short) 16, scratch, (short) 16);

        sha256.reset();
        sha256.doFinal(scratch, (short) 16, (short) 16, scratch, (short) 96);

        if (Util.arrayCompare(scratch, (short) 96, masterKeyHash, (short) 0, (short) 32) != 0) {
            pinTries++;
            ISOException.throwIt(Constants.SW_VERIFICATION_FAILED);
        }

        JCSystem.beginTransaction();
        try {
            // --- Key Rotation ---
            KeyPair tempPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            tempPair.genKeyPair();

            // Encrypt Private Key with MasterKey (scratch[16])
            encryptAndStorePrivateKey((RSAPrivateKey) tempPair.getPrivate(), scratch, (short) 16);

            // Store Public Key
            RSAPublicKey tempPub = (RSAPublicKey) tempPair.getPublic();
            short rsaLen = tempPub.getModulus(scratch, (short) 128);
            publicKey.setModulus(scratch, (short) 128, rsaLen);
            rsaLen = tempPub.getExponent(scratch, (short) 128);
            publicKey.setExponent(scratch, (short) 128, rsaLen);
            // ---------------------

            // Encrypt MasterKey with New PIN
            pbkdf2.derive(buffer, newPinOff, (short) 6, cardSalt, (short) 0, (short) 16, Constants.PBKDF2_ITERATIONS,
                    scratch, (short) 64);
            tempKey.setKey(scratch, (short) 64);

            aesCipher.init(tempKey, Cipher.MODE_ENCRYPT, zeroIV, (short) 0, (short) 16);
            aesCipher.doFinal(scratch, (short) 16, (short) 16, encryptedMasterKey, (short) 0);

            pinTries = 0;
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 256, (byte) 0);
    }

    // =========================================================================
    // PHAN 2: TRAO DOI KHOA & DUONG TRUYEN
    // =========================================================================

    public short signData(byte[] input, short inOff, short inLen, byte[] sigBuff, short sigOff) {
        // --- MODIFIED: DECRYPT ON DEMAND ---
        restorePrivateKey();

        try {
            rsaSignature.init(transientPrivateKey, Signature.MODE_SIGN);
            return rsaSignature.sign(input, inOff, inLen, sigBuff, sigOff);
        } finally {
            clearTransientPrivateKey();
        }
    }

    public RSAPublicKey getCardPublicKey() {
        if (!isSetup) {
            // Option: Throw error or return empty key
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        return publicKey;
    }

    public void setAppPublicKey(byte[] buffer, short offset, short len) {
        appPublicKey.setModulus(buffer, offset, len);
        byte[] exp = { 0x01, 0x00, 0x01 };
        appPublicKey.setExponent(exp, (short) 0, (short) 3);
    }

    // Ham ma hoa Hybrid: Tao SessionKey -> Encrypt Data -> Pack Gui di
    public short encryptAndPackData(byte[] inputData, short inOff, short inLen, byte[] apduBuffer, short outOff) {
        // 1. Tao Session Key ngau nhien (16 bytes AES)
        // Luu tam vao scratch[0..15]
        random.generateData(scratch, (short) 0, (short) 16);

        // Load vao tempKey (Tan dung doi tuong nay vi verify xong no ranh)
        tempKey.setKey(scratch, (short) 0);

        // 2. Ma hoa Session Key bang App Public Key (RSA)
        // Ghi ket qua (Encrypted Key) vao dau buffer out
        rsaCipher.init(appPublicKey, Cipher.MODE_ENCRYPT);
        short rsaBlockLen = rsaCipher.doFinal(scratch, (short) 0, (short) 16, apduBuffer, outOff);

        // 3. Ma hoa Du lieu bang Session Key (AES)
        // Ghi ket qua (Encrypted Data) noi tiep sau RSA block
        // *** FIX IV: Luon dung IV 0 de dong bo ***
        aesCipher.init(tempKey, Cipher.MODE_ENCRYPT, zeroIV, (short) 0, (short) 16);

        // Luu y: Input AES CBC phai la boi so cua 16. Applet phai dam bao dieu nay.
        short aesDataLen = aesCipher.doFinal(inputData, inOff, inLen, apduBuffer, (short) (outOff + rsaBlockLen));

        // Xoa session key trong RAM
        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 16, (byte) 0);

        // Tra ve tong do dai goi tin
        return (short) (rsaBlockLen + aesDataLen);
    }

    // Ham tai App Public Key tu buffer (Modulus 128 bytes)
    // Input: buffer chua RSA Modulus (128 bytes)
    public void loadAppPublicKey(byte[] buffer, short offset) {
        // Load Modulus vao appPublicKey
        appPublicKey.setModulus(buffer, offset, (short) 128);

        // Set Exponent (65537 = 0x010001)
        byte[] exp = { 0x01, 0x00, 0x01 };
        appPublicKey.setExponent(exp, (short) 0, (short) 3);
    }

    // --- UTILS ---
    public AESKey getMasterKey() {
        if (!isUnlocked)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        return masterKey;
    }

    public boolean isCardBlocked() {
        return pinTries >= Constants.PIN_MAX_TRIES;
    }

    public byte getPinTries() {
        return pinTries;
    }

    // --- FIRST TIME LOGIN STATE ---
    private boolean isFirstLogin;

    public void setFirstLogin(boolean status) {
        this.isFirstLogin = status;
    }

    public boolean isFirstLogin() {
        return this.isFirstLogin;
    }
}
