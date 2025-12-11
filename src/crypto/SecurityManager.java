package crypto;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import common.Constants;

public class SecurityManager {

    // --- CAC DOI TUONG KEY ---
    private AESKey masterKey; // Khoa chu (AES-128) - Dung de encrypt du lieu User
    private AESKey tempKey; // Khoa tam (AES-128) - Sinh ra tu PIN

    private KeyPair cardRsaKeyPair; // Cap khoa RSA cua the (Private + Public)
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
    private byte[] scratch;
    private byte[] zeroIV; // IV toan 0 de reset trang thai Cipher

    // --- TRANG THAI ---
    private boolean isUnlocked;
    private byte pinTries;

    public SecurityManager() {
        // 1. Khoi tao cac Key rong
        masterKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        tempKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        // 2. Init RSA (Tao cap khoa ngau nhien cho the ngay luc cai dat)
        cardRsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        cardRsaKeyPair.genKeyPair();

        // Tao object chua Key cua App (cho App gui xuong moi co du lieu)
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
        scratch = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_RESET);
        // IV toan 0 (Transient)
        zeroIV = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);

        isUnlocked = false;
        pinTries = 0;
    }

    // =========================================================================
    // PHAN 1: QUAN LY SETUP & PIN (DATA AT REST)
    // =========================================================================

    // HAM HELPER: Check Admin PIN (Tra ve true neu dung)
    // Luu y: Ham nay se luu Admin Key Plain vao scratch[80..95] de cac ham sau su
    // dung
    private boolean checkAdminPin(byte[] pinBuffer, short pinOffset) {
        // Derive AdminPIN -> Key thu (scratch[64])
        pbkdf2.derive(pinBuffer, pinOffset, (short) 6, adminSalt, (short) 0, (short) 16, Constants.PBKDF2_ITERATIONS,
                scratch, (short) 64);
        tempKey.setKey(scratch, (short) 64);

        // Giai ma encryptedAdminKey -> scratch[80]
        // *** FIX IV: Luon dung IV 0 de dong bo ***
        aesCipher.init(tempKey, Cipher.MODE_DECRYPT, zeroIV, (short) 0, (short) 16);
        aesCipher.doFinal(encryptedAdminKey, (short) 0, (short) 16, scratch, (short) 80);

        // Hash -> scratch[96]
        sha256.reset();
        sha256.doFinal(scratch, (short) 80, (short) 16, scratch, (short) 96);

        // Compare Hash
        return Util.arrayCompare(scratch, (short) 96, adminKeyHash, (short) 0, (short) 32) == 0;
    }

    public void processUnblockCard(byte[] buffer, short offset, short len) {
        // --- REMOVED DECRYPT ---
        // Nhan Plaintext Admin PIN (6 bytes)

        // Admin PIN = 6 bytes
        if (len < 6)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // 2. Verify Admin PIN
        if (checkAdminPin(buffer, offset)) {
            // Dung Admin PIN -> Reset counter
            pinTries = 0;
        } else {
            ISOException.throwIt(Constants.SW_VERIFICATION_FAILED);
        }

        // Xoa buffer (khong can thiet neu chi doc, nhung cu lam cho an toan)
        // Util.arrayFillNonAtomic(buffer, offset, len, (byte) 0);
    }

    // Ham giai ma Hybrid goi tin nhan vao (Dung cho Setup, Verify, Reset)
    // Input: [RSA_Encrypted_SessionKey (128 bytes)] + [AES_Encrypted_Data (16
    // bytes)]
    // Output: Ghi du lieu ro vao buffer
    // Tra ve: Do dai du lieu ro
    public short decryptIncomingData(byte[] buffer, short offset, short len) {
        // 1. Tach RSA block (Session Key)
        // Session Key encrypted nam o dau buffer
        rsaCipher.init(cardRsaKeyPair.getPrivate(), Cipher.MODE_DECRYPT);

        // Giai ma Session Key -> Luu tam vao scratch[0..15]
        // Do dai RSA 1024 bit = 128 bytes
        rsaCipher.doFinal(buffer, offset, (short) 128, scratch, (short) 0);

        // 2. Load Session Key vao TempKey
        tempKey.setKey(scratch, (short) 0);

        // 3. Giai ma Data AES
        // Data encrypted nam ngay sau RSA block
        short dataOff = (short) (offset + 128);
        short dataLen = (short) (len - 128);

        // *** FIX IV: Luon dung IV 0 de dong bo ***
        aesCipher.init(tempKey, Cipher.MODE_DECRYPT, zeroIV, (short) 0, (short) 16);
        short plainLen = aesCipher.doFinal(buffer, dataOff, dataLen, buffer, offset);

        // Xoa session key
        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 16, (byte) 0);

        return plainLen;
    }

    // Setup the lan dau (Secure Setup): Nhan PLAINTEXT
    // Input: [UserPIN (6)] + [AdminPIN (6)] = 12 bytes
    // Tu sinh UserKey va AdminKey ngau nhien
    public void setupCard(byte[] buffer, short offset, short len) {
        // --- REMOVED DECRYPT INCOMING DATA ---
        // Du lieu da la Plaintext, do dai phai dung 12 bytes
        if (len != 12)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short userPinOff = offset;
        short adminPinOff = (short) (offset + 6);

        JCSystem.beginTransaction();
        try {
            // --- XU LY USER KEY ---
            // 1. Sinh User MasterKey ngau nhien
            // Luu tam vao scratch[16..31]
            random.generateData(scratch, (short) 16, (short) 16);

            // 2. Tao Salt ngau nhien cho User
            random.generateData(cardSalt, (short) 0, (short) 16);

            // 3. Dan xuat UserPIN + Salt -> TempKey
            pbkdf2.derive(buffer, userPinOff, (short) 6, cardSalt, (short) 0, (short) 16, Constants.PBKDF2_ITERATIONS,
                    scratch, (short) 0);
            tempKey.setKey(scratch, (short) 0);

            // 4. Ma hoa User MasterKey bang TempKey -> encryptedMasterKey
            // *** FIX IV: Luon dung IV 0 de dong bo ***
            aesCipher.init(tempKey, Cipher.MODE_ENCRYPT, zeroIV, (short) 0, (short) 16);
            aesCipher.doFinal(scratch, (short) 16, (short) 16, encryptedMasterKey, (short) 0);

            // 5. Hash User MasterKey de danh doi chieu sau nay
            sha256.reset();
            sha256.doFinal(scratch, (short) 16, (short) 16, masterKeyHash, (short) 0);

            // --- XU LY ADMIN KEY ---
            // 6. Sinh Admin Key ngau nhien
            // Luu tam vao scratch[32..47] (Doi offset de khong ghi de MasterKey o
            // scratch[16])
            random.generateData(scratch, (short) 32, (short) 16);

            // 7. Tao Salt ngau nhien cho Admin
            random.generateData(adminSalt, (short) 0, (short) 16);

            // 8. Dan xuat AdminPIN + AdminSalt -> TempKey (Tai su dung tempKey)
            // Luu key derived vao scratch[64..79]
            pbkdf2.derive(buffer, adminPinOff, (short) 6, adminSalt, (short) 0, (short) 16, Constants.PBKDF2_ITERATIONS,
                    scratch, (short) 64);
            tempKey.setKey(scratch, (short) 64);

            // 9. Ma hoa AdminKey (dang o scratch[32]) bang TempKey -> encryptedAdminKey
            aesCipher.init(tempKey, Cipher.MODE_ENCRYPT, zeroIV, (short) 0, (short) 16);
            aesCipher.doFinal(scratch, (short) 32, (short) 16, encryptedAdminKey, (short) 0);

            // 10. Hash AdminKey de danh doi chieu sau nay
            sha256.reset();
            sha256.doFinal(scratch, (short) 32, (short) 16, adminKeyHash, (short) 0);

            // --- BACKUP MASTER KEY (NEW) ---
            // 11. Ma hoa MasterKey (scratch[16]) bang AdminKey (scratch[32]) ->
            // encryptedMasterKeyByAdmin
            tempKey.setKey(scratch, (short) 32); // Load AdminKey
            aesCipher.init(tempKey, Cipher.MODE_ENCRYPT, zeroIV, (short) 0, (short) 16);
            aesCipher.doFinal(scratch, (short) 16, (short) 16, encryptedMasterKeyByAdmin, (short) 0);

            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 128, (byte) 0);
    }

    // Ham reset User Key bang Admin Key (Khi quen User PIN)
    // Input: [AdminPIN 6] + [NewUserPIN 6] (MasterKey tu sinh)
    // Giai ma: AdminPIN + NewUserPIN = 12 bytes
    public void resetUserKey(byte[] buffer, short offset) {
        // buffer[offset] la AdminPIN
        // buffer[offset+6] la NewUserPIN

        short adminPinOff = offset;
        short newUserPinOff = (short) (offset + 6);

        // 1. Xac thuc Admin PIN truoc (Dung Helper moi)
        if (!checkAdminPin(buffer, adminPinOff)) {
            // DEBUG: Bao loi Hash Admin khong khop
            short debugHash = (short) (0x6600 | (scratch[96] & 0xFF));
            ISOException.throwIt(debugHash);
        }

        // --- ADMIN DUNG -> TIEN HANH RESET USER KEY ---
        // AdminKey Plain dang o scratch[80..95] (do checkAdminPin da giai ma va de do)

        JCSystem.beginTransaction();
        try {
            // 1. Khoi phuc MasterKey cu tu Ban Backup (encryptedMasterKeyByAdmin)
            // Dung AdminKey (scratch[80]) de giai ma
            tempKey.setKey(scratch, (short) 80);
            aesCipher.init(tempKey, Cipher.MODE_DECRYPT, zeroIV, (short) 0, (short) 16);
            // Giai ma -> MasterKey Plain -> scratch[16..31]
            aesCipher.doFinal(encryptedMasterKeyByAdmin, (short) 0, (short) 16, scratch, (short) 16);

            // --- ADDED: Generate New RSA KeyPair (Key Rotation) ---
            cardRsaKeyPair.genKeyPair();

            // 2. Dan xuat NewUserPIN + OldSalt -> TempKey (Dung de ma hoa lai MasterKey)
            // scratch[64..79]
            pbkdf2.derive(buffer, newUserPinOff, (short) 6, cardSalt, (short) 0, (short) 16,
                    Constants.PBKDF2_ITERATIONS, scratch, (short) 64);
            tempKey.setKey(scratch, (short) 64);

            // 3. Ma hoa MasterKey Cu (scratch[16]) bang NewUserPIN -> Luu vao
            // encryptedMasterKey
            aesCipher.init(tempKey, Cipher.MODE_ENCRYPT, zeroIV, (short) 0, (short) 16);
            aesCipher.doFinal(scratch, (short) 16, (short) 16, encryptedMasterKey, (short) 0);

            // 4. Hash MasterKey (de dam bao tinh toan ven, du la key cu thi hash van phai
            // giong cu)
            // (Thuc ra buoc nay hoi thua vi MasterKey khong doi, nhung cu lam cho chac)
            sha256.reset();
            sha256.doFinal(scratch, (short) 16, (short) 16, masterKeyHash, (short) 0);

            // Reset so lan thu PIN
            pinTries = 0;

            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 128, (byte) 0);
    }

    // Ham xac thuc PIN (Dau vao la PLAINTEXT)
    // Input: [PIN 6 bytes] (hoac duoc pad thanh 16)
    public void verifyPin(byte[] buffer, short offset, short len) {
        if (pinTries >= Constants.PIN_MAX_TRIES)
            ISOException.throwIt(Constants.SW_CARD_LOCKED);

        // --- REMOVED DECRYPT ---

        // Client gui: 6 bytes PIN. Len co the lon hon neu padding
        if (len < 6)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // 2. Goi ham verify noi bo voi PIN tran (lay 6 bytes thuc)
        verifyPinInternal(buffer, offset, (short) 6);

        // 3. Xoa ngay buffer chua PIN tran (Optional neu can secure memory, nhung day
        // la RAM buffer cua APDU)
    }

    // Ham noi bo: Logic PBKDF2 de mo khoa MasterKey
    private void verifyPinInternal(byte[] pin, short pinOff, short pinLen) {
        // 1. PIN + SaltStored -> TempKey
        // Ket qua Key nam o scratch[64..79] (de tranh ghi de len PIN o doan dau)
        pbkdf2.derive(pin, pinOff, pinLen, cardSalt, (short) 0, (short) 16, Constants.PBKDF2_ITERATIONS, scratch,
                (short) 64);
        tempKey.setKey(scratch, (short) 64);

        // 2. Dung TempKey giai ma EncryptedMasterKey -> Luu vao scratch[80..95]
        // *** FIX IV: Luon dung IV 0 de dong bo ***
        aesCipher.init(tempKey, Cipher.MODE_DECRYPT, zeroIV, (short) 0, (short) 16);
        aesCipher.doFinal(encryptedMasterKey, (short) 0, (short) 16, scratch, (short) 80);

        // 3. Hash ket qua vua giai ma -> Luu vao scratch[96..127]
        sha256.reset();
        sha256.doFinal(scratch, (short) 80, (short) 16, scratch, (short) 96);

        // 4. So sanh voi Hash goc
        if (Util.arrayCompare(scratch, (short) 96, masterKeyHash, (short) 0, (short) 32) == 0) {
            // DUNG PIN!
            pinTries = 0;
            isUnlocked = true;
            // Load MasterKey that vao object de dung cho session nay
            masterKey.setKey(scratch, (short) 80);
        } else {
            // SAI PIN
            pinTries++;
            isUnlocked = false;
            // DEBUG: Nem ma loi 66XX de biet Hash sai
            short debugHash = (short) (0x6600 | (scratch[96] & 0xFF));
            ISOException.throwIt(debugHash);
            // ISOException.throwIt(Constants.SW_VERIFICATION_FAILED);
        }
    }

    // Xu ly goi tin Reset User Key (Ma hoa Hybrid)
    // Packet: [RSA 128 bytes] + [AES Encrypted (AdminPIN 6 + NewUserPIN 6 + Pad 4)
    // 16 bytes]
    public void processResetUserKey(byte[] buffer, short offset, short len) {
        // --- REMOVED DECRYPT ---

        // Tong data phai la 12 bytes (6 Admin + 6 User)
        if (len < 12)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // 2. Goi ham resetUserKey voi du lieu da giai ma
        resetUserKey(buffer, offset);

        // 3. Xoa buffer nhay cam
        // Util.arrayFillNonAtomic(buffer, offset, plainLen, (byte) 0);
    }

    // Change PIN (Plaintext)
    // Packet: [OldPIN 6] + [NewPIN 6]
    public void changePin(byte[] buffer, short offset, short len) {
        // --- REMOVED DECRYPT ---
        if (len < 12)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        changePinInternal(buffer, offset);

        // Xoa buffer (Optional)
    }

    // Helper: Logic Change PIN (Input la Plaintext)
    private void changePinInternal(byte[] buffer, short offset) {
        short oldPinOff = offset;
        short newPinOff = (short) (offset + 6);

        // 1. Verify Old PIN
        // Derive OldPIN -> scratch[64]
        pbkdf2.derive(buffer, oldPinOff, (short) 6, cardSalt, (short) 0, (short) 16, Constants.PBKDF2_ITERATIONS,
                scratch, (short) 64);
        tempKey.setKey(scratch, (short) 64);

        // Decrypt EncryptedMasterKey -> scratch[16] (MasterKey Plain)
        aesCipher.init(tempKey, Cipher.MODE_DECRYPT, zeroIV, (short) 0, (short) 16);
        aesCipher.doFinal(encryptedMasterKey, (short) 0, (short) 16, scratch, (short) 16);

        // Validate Hash
        sha256.reset();
        sha256.doFinal(scratch, (short) 16, (short) 16, scratch, (short) 96);

        if (Util.arrayCompare(scratch, (short) 96, masterKeyHash, (short) 0, (short) 32) != 0) {
            pinTries++;
            ISOException.throwIt(Constants.SW_VERIFICATION_FAILED);
        }

        // --- OLD PIN CORRECT ---

        JCSystem.beginTransaction();
        try {
            // --- ADDED: Generate New RSA KeyPair (Key Rotation) ---
            cardRsaKeyPair.genKeyPair();

            // 2. Derive NewPIN -> NewKey (scratch[64])
            pbkdf2.derive(buffer, newPinOff, (short) 6, cardSalt, (short) 0, (short) 16, Constants.PBKDF2_ITERATIONS,
                    scratch, (short) 64);
            tempKey.setKey(scratch, (short) 64);

            // 3. Encrypt MasterKey (scratch[16]) bang NewKey -> encryptedMasterKey
            aesCipher.init(tempKey, Cipher.MODE_ENCRYPT, zeroIV, (short) 0, (short) 16);
            aesCipher.doFinal(scratch, (short) 16, (short) 16, encryptedMasterKey, (short) 0);

            pinTries = 0;
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 128, (byte) 0);
    }

    // =========================================================================
    // PHAN 2: TRAO DOI KHOA & DUONG TRUYEN (DATA IN TRANSIT)
    // =========================================================================

    public short signData(byte[] input, short inOff, short inLen, byte[] sigBuff, short sigOff) {
        // 1. Init Signature voi Private Key
        rsaSignature.init(cardRsaKeyPair.getPrivate(), Signature.MODE_SIGN);

        // 2. Ky du lieu
        return rsaSignature.sign(input, inOff, inLen, sigBuff, sigOff);
    }

    public RSAPublicKey getCardPublicKey() {
        return (RSAPublicKey) cardRsaKeyPair.getPublic();
    }

    public void setAppPublicKey(byte[] buffer, short offset, short len) {
        // Gia su App gui Modulus (RSA Key Components)
        appPublicKey.setModulus(buffer, offset, len);
        byte[] exp = { 0x01, 0x00, 0x01 }; // Exponent mac dinh 65537
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
}
