package common;

public class Constants {
    // --- APPLET ---
    public static final byte CLA_BOOKSTORE = (byte) 0x00;

    // --- INSTRUCTION (INS) ---
    public static final byte INS_SETUP_CARD = (byte) 0x10; // Setup Key
    public static final byte INS_INIT_DATA = (byte) 0x15; // Nap thong tin user lan dau (New)
    public static final byte INS_VERIFY_PIN = (byte) 0x20; // Login
    public static final byte INS_GET_PUBLIC_KEY = (byte) 0x22;
    public static final byte INS_CHANGE_PIN = (byte) 0x25; // Change PIN
    public static final byte INS_GET_INFO = (byte) 0x30;
    public static final byte INS_AUTH_GET_CARD_ID = (byte) 0x31; // Auth Step 1
    public static final byte INS_UPDATE_INFO = (byte) 0x40;
    public static final byte INS_RESET_USER_KEY = (byte) 0x50;
    public static final byte INS_SET_APP_KEY = 0x24;

    // --- ERROR CODES ---
    public static final short SW_VERIFICATION_FAILED = (short) 0x6300;
    public static final short SW_CARD_LOCKED = (short) 0x6983;

    // --- CAU TRUC BO NHO DU LIEU (DATA MAP) ---
    // Tong dung luong bo nho danh cho User Data: 2KB
    public static final short DATA_SIZE = (short) 2048; // Tang de chua App Public Key

    // 1. Card ID (16 bytes)
    public static final short OFF_CARD_ID = (short) 0;
    public static final short LEN_CARD_ID = (short) 16;

    // 2. Ho ten (64 bytes)
    public static final short OFF_FULLNAME = (short) 16;
    public static final short LEN_FULLNAME = (short) 64;

    // 3. Ngay sinh (16 bytes - DDMMYYYY + Padding) - NEW
    public static final short OFF_DOB = (short) 80;
    public static final short LEN_DOB = (short) 16;

    // 4. So dien thoai (16 bytes) - Doi cho
    public static final short OFF_PHONE = (short) 96;
    public static final short LEN_PHONE = (short) 16;

    // 5. Ngay dang ky (16 bytes - DDMMYYYY + Padding) - NEW
    public static final short OFF_REG_DATE = (short) 112;
    public static final short LEN_REG_DATE = (short) 16;

    // 6. Diem tich luy (16 bytes) - Doi cho
    public static final short OFF_POINTS = (short) 128;
    public static final short LEN_POINTS = (short) 16;

    // 7. Anh/Avatar (1024 bytes) - NEW
    public static final short OFF_IMAGE = (short) 144;
    public static final short LEN_IMAGE = (short) 1024;

    // 8. App Public Key (128 bytes - RSA Modulus) - NEW
    public static final short OFF_APP_PUBLIC_KEY = (short) 1168; // 144 + 1024
    public static final short LEN_APP_PUBLIC_KEY = (short) 128;

    // --- SECURITY ---
    public static final short PBKDF2_ITERATIONS = (short) 500;
    public static final byte PIN_MAX_TRIES = (byte) 3;
}
