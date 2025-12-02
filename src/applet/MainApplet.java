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
    private byte[] tempBufferRam; // Bo dem RAM cho data lon

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MainApplet();
    }

    protected MainApplet() {
        secManager = new SecurityManager();
        repository = new DataRepository();

        // Cap phat bo dem RAM (Transient ByteArray) de xu ly APDU lon
        // Size 512 du chua 320 bytes du lieu
        tempBufferRam = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);

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
                // Nhan PIN Plaintext
                // [PIN 6 bytes] (hoac 16 bytes do padding)
                short dataLen = apdu.setIncomingAndReceive();
                secManager.verifyPin(buffer, ISO7816.OFFSET_CDATA, dataLen);
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
        // Giai doan Setup (PLAINTEXT)
        // Nhan [UserPIN (6)] + [AdminPIN (6)]
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // Goi ham setup moi (tu sinh key)
        secManager.setupCard(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void handleChangePin(APDU apdu) {
        // Nhan [OldPIN 6] + [NewPIN 6] (Plaintext)
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        // Goi ham changePin Plaintext
        secManager.changePin(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void handleUnblockPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        secManager.processUnblockCard(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void handleResetUserKey(APDU apdu) {
        // Nhan [AdminPIN (6)] + [NewUserPIN (6)] = 12 bytes (Plaintext)
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // Goi ham xu ly Plaintext
        secManager.processResetUserKey(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void handleInitData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = 0;
        // 1. Kiem tra do dai du kien (Lc)
        // Voi Extended APDU, phai dung getIncomingLength() de lay full length
        short len = apdu.setIncomingAndReceive();

        // FIX: Copy data tu offset data thuc te (apdu.getOffsetCdata()) thay vi
        // ISO7816.OFFSET_CDATA (5)
        // Dieu nay tranh viec copy nham header neu dung extended APDU header
        Util.arrayCopy(buffer, apdu.getOffsetCdata(), tempBufferRam, offset, len);
        offset += len;

        while (len > 0) {
            len = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
            Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, tempBufferRam, offset, len);
            offset += len;
        }

        // Expect: 320 bytes
        if (offset < (short) 320) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // 3. Parse Data tu tempBufferRam
        // Structure: [CardID (16)] [Name (64)] [DOB (16)] [Phone (16)] [Address (64)]
        // [RegDate (16)] [AppPublicKey (128)]

        AESKey mk = secManager.getMasterKey();
        short readOff = 0;

        // Write CardID
        repository.write(Constants.OFF_CARD_ID, tempBufferRam, readOff, Constants.LEN_CARD_ID, mk);
        readOff += Constants.LEN_CARD_ID;

        // Write Name
        repository.write(Constants.OFF_FULLNAME, tempBufferRam, readOff, Constants.LEN_FULLNAME, mk);
        readOff += Constants.LEN_FULLNAME;

        // Write DOB
        repository.write(Constants.OFF_DOB, tempBufferRam, readOff, Constants.LEN_DOB, mk);
        readOff += Constants.LEN_DOB;

        // Write Phone (NEW)
        repository.write(Constants.OFF_PHONE, tempBufferRam, readOff, Constants.LEN_PHONE, mk);
        readOff += Constants.LEN_PHONE;

        // Write Address (NEW)
        repository.write(Constants.OFF_ADDRESS, tempBufferRam, readOff, Constants.LEN_ADDRESS, mk);
        readOff += Constants.LEN_ADDRESS;

        // Write RegDate
        repository.write(Constants.OFF_REG_DATE, tempBufferRam, readOff, Constants.LEN_REG_DATE, mk);
        readOff += Constants.LEN_REG_DATE;

        // Write App Public Key (128 bytes)
        repository.write(Constants.OFF_APP_PUBLIC_KEY, tempBufferRam, readOff, Constants.LEN_APP_PUBLIC_KEY, mk);
    }

    private void handleAuthGetCardId(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        // --- REMOVED HYBRID ENCRYPTION ---
        // Chi gui Plaintext CardID (16 bytes)

        // 1. Chuan bi Response (16 bytes)
        apdu.setOutgoing();
        apdu.setOutgoingLength(Constants.LEN_CARD_ID);

        // 2. Doc CardID (Plaintext) vao buffer tai offset 0
        repository.read(Constants.OFF_CARD_ID, Constants.LEN_CARD_ID, buffer, (short) 0, mk);

        // 3. Gui
        apdu.sendBytes((short) 0, Constants.LEN_CARD_ID);
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

        // --- KHONG DUNG MA HOA HYBRID NUA, GUI PLAINTEXT ---

        // 1. Chuan bi Response (Data 192 bytes)
        // Data: CardID(16) + Name(64) + DOB(16) + Phone(16) + Address(64) + RegDate(16)
        // = 192 bytes
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 192);

        short plainOff = 0; // Ghi truc tiep tu dau buffer

        // Doc du lieu tu EEPROM (da giai ma bang MasterKey) va ghi thang vao buffer
        repository.read(Constants.OFF_CARD_ID, Constants.LEN_CARD_ID, buffer, plainOff, mk);
        plainOff += Constants.LEN_CARD_ID;

        repository.read(Constants.OFF_FULLNAME, Constants.LEN_FULLNAME, buffer, plainOff, mk);
        plainOff += Constants.LEN_FULLNAME;

        repository.read(Constants.OFF_DOB, Constants.LEN_DOB, buffer, plainOff, mk);
        plainOff += Constants.LEN_DOB;

        repository.read(Constants.OFF_PHONE, Constants.LEN_PHONE, buffer, plainOff, mk);
        plainOff += Constants.LEN_PHONE;

        repository.read(Constants.OFF_ADDRESS, Constants.LEN_ADDRESS, buffer, plainOff, mk);
        plainOff += Constants.LEN_ADDRESS;

        repository.read(Constants.OFF_REG_DATE, Constants.LEN_REG_DATE, buffer, plainOff, mk);
        // plainOff luc nay = 192

        // 2. Gui toan bo
        apdu.sendBytes((short) 0, (short) 192);
    }
}
