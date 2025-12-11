package common;

public class Constants {
    // --- APPLET ---
    public static final byte CLA_BOOKSTORE = (byte) 0x00;

    // --- INSTRUCTION (INS) ---
    public static final byte INS_SETUP_CARD = (byte) 0x10; // Setup Key
    public static final byte INS_INIT_DATA = (byte) 0x15; // Nap thong tin user (Text + AppKey)
    public static final byte INS_UPLOAD_IMAGE = (byte) 0x16; // Upload Anh (New)
    public static final byte INS_VERIFY_PIN = (byte) 0x20; // Login
    public static final byte INS_GET_PUBLIC_KEY = (byte) 0x22;
    public static final byte INS_CHANGE_PIN = (byte) 0x25; // Change PIN
    public static final byte INS_GET_INFO = (byte) 0x30;
    public static final byte INS_AUTH_GET_CARD_ID = (byte) 0x31; // Auth Step 1
    public static final byte INS_AUTH_CHALLENGE = (byte) 0x32; // Auth Step 2
    public static final byte INS_GET_PIN_TRIES = (byte) 0x33; // Get PIN Tries
    public static final byte INS_GET_IMAGE = (byte) 0x34; // Get Image (New)
    public static final byte INS_UNBLOCK_PIN = (byte) 0x26; // Unblock PIN
    public static final byte INS_UPDATE_INFO = (byte) 0x40;
    public static final byte INS_SET_APP_KEY = 0x24;
    public static final byte INS_RESET_USER_PIN = (byte) 0x50;

    // --- INS BALANCE ---
    public static final byte INS_GET_BALANCE = (byte) 0x53;
    public static final byte INS_DEPOSIT = (byte) 0x54;
    public static final byte INS_PAYMENT = (byte) 0x55;

    // --- INS MEMBERSHIP & BORROW ---
    public static final byte INS_UPGRADE_SILVER = (byte) 0x60;
    public static final byte INS_UPGRADE_GOLD = (byte) 0x61;
    public static final byte INS_UPGRADE_DIAMOND = (byte) 0x62;

    public static final byte INS_BORROW_BOOK = (byte) 0x56;
    public static final byte INS_RETURN_BOOK = (byte) 0x57;
    public static final byte INS_GET_BORROWED_BOOKS = (byte) 0x58;
    public static final byte INS_ADD_POINT = (byte) 0x59;

    // --- ERROR CODES ---
    public static final short SW_VERIFICATION_FAILED = (short) 0x6300;
    public static final short SW_CARD_LOCKED = (short) 0x6983;

    // --- CAU TRUC BO NHO DU LIEU (DATA MAP) ---
    // Tong dung luong bo nho: 24KB (Cho 20KB anh + 2KB Data + Du phong)
    // Gioi han Short: 32767
    public static final short DATA_SIZE = (short) 24576;

    // 1. Card ID (16 bytes)
    public static final short OFF_CARD_ID = (short) 0;
    public static final short LEN_CARD_ID = (short) 16;

    // 2. Ho ten (64 bytes)
    public static final short OFF_FULLNAME = (short) 16;
    public static final short LEN_FULLNAME = (short) 64;

    // 3. Ngay sinh (16 bytes)
    public static final short OFF_DOB = (short) 80;
    public static final short LEN_DOB = (short) 16;

    // 4. So dien thoai (16 bytes)
    public static final short OFF_PHONE = (short) 96;
    public static final short LEN_PHONE = (short) 16;

    // 5. Dia chi (64 bytes)
    public static final short OFF_ADDRESS = (short) 112;
    public static final short LEN_ADDRESS = (short) 64;

    // 6. Ngay dang ky (16 bytes)
    public static final short OFF_REG_DATE = (short) 176;
    public static final short LEN_REG_DATE = (short) 16;

    // 7. App Public Key (128 bytes)
    public static final short OFF_APP_PUBLIC_KEY = (short) 192;
    public static final short LEN_APP_PUBLIC_KEY = (short) 128;

    // 8. Balance (So du tai khoan) - Luu 16 bytes (4 bytes so + 12 bytes padding)
    // de tron Block AES
    public static final short OFF_BALANCE = (short) 320;
    public static final short LEN_BALANCE = (short) 16;

    // 9. Points (Diem tich luy) - Luu 16 bytes (4 bytes so + 12 bytes padding)
    public static final short OFF_POINTS = (short) 336;
    public static final short LEN_POINTS = (short) 16;

    // 10. Member Type (16 bytes)
    // Offset = 336 + 16 = 352
    public static final short OFF_MEMBER_TYPE = (short) 352;
    public static final short LEN_MEMBER_TYPE = (short) 16;

    // 11. Borrowed Books Data (Max 15 books)
    // Moi slot 16 bytes: 7 (ID) + 8 (Date) + 1 (Duration)
    // Total len = 15 * 16 = 240 bytes
    // Offset = 352 + 16 = 368
    public static final short OFF_BORROW_DATA = (short) 368;
    public static final short LEN_BORROW_DATA = (short) 240;
    public static final byte MAX_BORROWED_BOOKS = (byte) 15;
    public static final byte LEN_BOOK_SLOT = (byte) 16;

    // 12. Image (20480 bytes = 20KB)
    // Offset = 368 + 240 = 608
    public static final short OFF_IMAGE = (short) 608;
    public static final short LEN_IMAGE = (short) 20480;

    // --- SECURITY ---
    public static final short PBKDF2_ITERATIONS = (short) 500;
    public static final byte PIN_MAX_TRIES = (byte) 3;
}
