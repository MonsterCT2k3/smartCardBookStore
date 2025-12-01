package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import common.Constants;
import crypto.SecurityManager;
import storage.DataRepository;

public class MainApplet extends Applet implements ExtendedLength {

    private SecurityManager secManager;
    private DataRepository repository;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MainApplet();
    }

    protected MainApplet() {
        secManager = new SecurityManager();
        repository = new DataRepository();
        register();
    }

    public void process(APDU apdu) {
        if (selectingApplet())
            return;

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        // Kiem tra xem the co bi khoa cung khong
        // CHO PHEP LENH UNBLOCK, RESET PIN, va GET PUBLIC KEY CHAY KHI KHOA
        if (secManager.isCardBlocked()
                && ins != Constants.INS_UNBLOCK_PIN
                && ins != Constants.INS_RESET_USER_KEY
                && ins != Constants.INS_GET_PUBLIC_KEY
                && ins != Constants.INS_GET_PIN_TRIES) {
            ISOException.throwIt(Constants.SW_CARD_LOCKED);
        }

        switch (ins) {
            // --- NHOM 1: SETUP & HANDSHAKE ---

            case Constants.INS_SETUP_CARD:
                handleSetup(apdu);
                break;

            case Constants.INS_CHANGE_PIN:
                handleChangePin(apdu);
                break;

            case Constants.INS_UNBLOCK_PIN:
                handleUnblockPin(apdu);
                break;

            case Constants.INS_RESET_USER_KEY:
                handleResetUserKey(apdu);
                break;

            case Constants.INS_GET_PUBLIC_KEY:
                // Gui Public Key cua the len App
                RSAPublicKey pubKey = secManager.getCardPublicKey();
                // Lay Modulus (thuong 128 bytes) ghi vao buffer
                short len = pubKey.getModulus(buffer, (short) 0);
                apdu.setOutgoingAndSend((short) 0, len);
                break;

            case (byte) 0x24: // INS_SET_APP_KEY (Ban nho them vao Constants nhe)
                // Nhan Public Key tu App
                short keyLen = apdu.setIncomingAndReceive();
                secManager.setAppPublicKey(buffer, ISO7816.OFFSET_CDATA, keyLen);
                break;

            // --- NHOM 2: LOGIN ---

            case Constants.INS_VERIFY_PIN:
                // Nhan goi Hybrid Encrypted PIN
                // [RSA SessionKey] + [AES PIN]
                short dataLen = apdu.setIncomingAndReceive();
                secManager.verifyPinHybrid(buffer, ISO7816.OFFSET_CDATA, dataLen);
                break;

            // --- NHOM 3: NGHIEP VU (CO MA HOA HYBRID) ---

            case Constants.INS_GET_INFO:
                handleGetInfoSecure(apdu);
                break;

            case Constants.INS_AUTH_GET_CARD_ID:
                handleAuthGetCardId(apdu);
                break;

            case Constants.INS_AUTH_CHALLENGE:
                handleAuthChallenge(apdu);
                break;

            case Constants.INS_GET_PIN_TRIES:
                handleGetPinTries(apdu);
                break;

            case Constants.INS_UPDATE_INFO:
                // Logic update info tuong tu (Decrypt goi tin -> Ghi vao DB)
                // (Phan nay ban tu trien khai dua tren logic nguoc lai cua Get Info)
                break;

            case Constants.INS_INIT_DATA:
                handleInitData(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void handleSetup(APDU apdu) {
        // Giai doan Setup Secure
        // Nhan goi tin ma hoa Hybrid chua [UserPIN (6)] + [AdminPIN (6)]
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // Goi ham setup moi (tu sinh key)
        secManager.setupCard(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void handleChangePin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        secManager.processChangePinHybrid(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void handleUnblockPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        secManager.processUnblockCard(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void handleResetUserKey(APDU apdu) {
        // Lenh nay nhan goi tin Hybrid chua:
        // [AdminPIN (6)] + [NewUserPIN (6)] = 12 bytes (sau giai ma AES)
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // 1. Decrypt goi Hybrid truoc (Goi xuong SecManager de xu ly tron goi)
        secManager.processResetUserKeyHybrid(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void handleInitData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        // Voi Extended APDU, ham nay nhan so luong byte thuc te dang co trong buffer
        // RAM
        short len = apdu.setIncomingAndReceive();

        // 1. Check Auth
        AESKey mk = secManager.getMasterKey();

        // 2. Parse Data
        // Client gui: [CardID (16)] [Name (64)] [DOB (16)] [RegDate (16)] [AppPublicKey
        // (128)]
        // Tong: 240 bytes (KHONG co Image)

        if (len < (short) 240) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short off = ISO7816.OFFSET_CDATA;

        // Write CardID
        repository.write(Constants.OFF_CARD_ID, buffer, off, Constants.LEN_CARD_ID, mk);
        off += Constants.LEN_CARD_ID;

        // Write Name
        repository.write(Constants.OFF_FULLNAME, buffer, off, Constants.LEN_FULLNAME, mk);
        off += Constants.LEN_FULLNAME;

        // Write DOB
        repository.write(Constants.OFF_DOB, buffer, off, Constants.LEN_DOB, mk);
        off += Constants.LEN_DOB;

        // Write RegDate
        repository.write(Constants.OFF_REG_DATE, buffer, off, Constants.LEN_REG_DATE, mk);
        off += Constants.LEN_REG_DATE;

        // Write App Public Key (128 bytes)
        repository.write(Constants.OFF_APP_PUBLIC_KEY, buffer, off, Constants.LEN_APP_PUBLIC_KEY, mk);
    }

    private void handleAuthGetCardId(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        // 1. Load App Public Key
        repository.read(Constants.OFF_APP_PUBLIC_KEY, Constants.LEN_APP_PUBLIC_KEY, buffer, (short) 0, mk);
        secManager.loadAppPublicKey(buffer, (short) 0);

        // 2. Chuan bi Response (RSA 128 + Data 16 = 144 bytes)
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 144);

        // 3. Doc CardID (Plaintext) vao buffer tai offset 128 (sau RSA block)
        repository.read(Constants.OFF_CARD_ID, Constants.LEN_CARD_ID, buffer, (short) 128, mk);

        // 4. Ma hoa Hybrid
        // Input: buffer[128..143] (16 bytes)
        // Output: buffer[0..143]
        secManager.encryptAndPackData(buffer, (short) 128, Constants.LEN_CARD_ID, buffer, (short) 0);

        // 5. Gui
        apdu.sendBytes((short) 0, (short) 144);
    }

    private void handleAuthChallenge(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive(); // Nhan Challenge (Random Bytes) tu Client

        // 1. Ky vao du lieu Challenge nhan duoc
        // Ghi chu ky de len chinh buffer input (vi challenge khong can dung nua)
        // Offset 0: Noi ghi chu ky tra ve
        short sigLen = secManager.signData(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0);

        // 2. Gui chu ky ve cho Client
        apdu.setOutgoingAndSend((short) 0, sigLen);
    }

    private void handleGetPinTries(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        // 1. Lay Pin Tries
        byte tries = secManager.getPinTries();

        // 2. Ghi vao buffer
        buffer[0] = tries;

        // 3. Gui 1 byte (Plaintext)
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    private void handleGetInfoSecure(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        // 1. Doc App Public Key & Load
        repository.read(Constants.OFF_APP_PUBLIC_KEY, Constants.LEN_APP_PUBLIC_KEY, buffer, (short) 0, mk);
        secManager.loadAppPublicKey(buffer, (short) 0);

        // 2. Chuan bi Response (RSA 128 + Data 112 = 240 bytes)
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 240);

        // 3. Doc toan bo Plaintext Data vao buffer (bat dau tu offset 128)
        // De danh cho cho RSA Block (0-127)
        short plainOff = 128;

        repository.read(Constants.OFF_CARD_ID, Constants.LEN_CARD_ID, buffer, plainOff, mk);
        plainOff += Constants.LEN_CARD_ID;

        repository.read(Constants.OFF_FULLNAME, Constants.LEN_FULLNAME, buffer, plainOff, mk);
        plainOff += Constants.LEN_FULLNAME;

        repository.read(Constants.OFF_DOB, Constants.LEN_DOB, buffer, plainOff, mk);
        plainOff += Constants.LEN_DOB;

        repository.read(Constants.OFF_REG_DATE, Constants.LEN_REG_DATE, buffer, plainOff, mk);
        // plainOff luc nay la 240

        // 4. Ma hoa Hybrid (RSA + AES)
        // Input: buffer[128..239] (112 bytes)
        // Output: buffer[0..239] (RSA 128 + AES 112)
        secManager.encryptAndPackData(buffer, (short) 128, (short) 112, buffer, (short) 0);

        // 5. Gui toan bo
        apdu.sendBytes((short) 0, (short) 240);
    }
}
