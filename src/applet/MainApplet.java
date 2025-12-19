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
                && ins != Constants.INS_RESET_USER_PIN
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

            case Constants.INS_RESET_USER_PIN:
                handleResetUserKey(apdu);
                break;

            case Constants.INS_GET_PUBLIC_KEY:
                // Gui Public Key cua the len App
                RSAPublicKey pubKey = secManager.getCardPublicKey();
                // Lay Modulus (thuong 128 bytes) ghi vao buffer
                short len = pubKey.getModulus(buffer, (short) 0);
                apdu.setOutgoingAndSend((short) 0, len);
                break;

            case (byte) 0x24: // INS_SET_APP_KEY
                // Nhan Public Key tu App
                short keyLen = apdu.setIncomingAndReceive();
                secManager.setAppPublicKey(buffer, ISO7816.OFFSET_CDATA, keyLen);
                break;

            // --- NHOM 2: LOGIN ---

            case Constants.INS_VERIFY_PIN:
                // Nhan PIN Plaintext
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
                handleUpdateInfo(apdu);
                break;

            case Constants.INS_INIT_DATA:
                handleInitData(apdu);
                break;

            case Constants.INS_UPLOAD_IMAGE:
                handleUploadImage(apdu);
                break;

            case Constants.INS_GET_IMAGE:
                handleGetImage(apdu);
                break;

            // --- NHOM 4: VI TIEN (BALANCE) ---
            case Constants.INS_GET_BALANCE:
                handleGetBalance(apdu);
                break;
            case Constants.INS_DEPOSIT:
                handleDeposit(apdu);
                break;
            case Constants.INS_PAYMENT:
                handlePayment(apdu);
                break;
            case Constants.INS_ADD_POINT:
                handleAddPoint(apdu);
                break;
            case Constants.INS_USE_POINT:
                handleUsePoint(apdu);
                break;

            // --- NHOM 5: MEMBERSHIP ---
            case Constants.INS_CHECK_FIRST_LOGIN:
                handleCheckFirstLogin(apdu);
                break;

            case Constants.INS_DISABLE_FIRST_LOGIN:
                handleDisableFirstLogin(apdu);
                break;

            case Constants.INS_UPGRADE_SILVER:
                handleUpgradeMember(apdu, (byte) 1);
                break;
            case Constants.INS_UPGRADE_GOLD:
                handleUpgradeMember(apdu, (byte) 2);
                break;
            case Constants.INS_UPGRADE_DIAMOND:
                handleUpgradeMember(apdu, (byte) 3);
                break;

            // --- NHOM 6: BORROW BOOKS ---
            case Constants.INS_BORROW_BOOK:
                handleBorrowBook(apdu);
                break;
            case Constants.INS_RETURN_BOOK:
                handleReturnBook(apdu);
                break;
            case Constants.INS_GET_BORROWED_BOOKS:
                handleGetBorrowedBooks(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void handleSetup(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        secManager.setupCard(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void handleChangePin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        secManager.changePin(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void handleUnblockPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        secManager.processUnblockCard(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void handleResetUserKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        secManager.processResetUserKey(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void handleInitData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = 0;
        short len = apdu.setIncomingAndReceive();

        // FIX: Copy data tu offset data thuc te
        Util.arrayCopy(buffer, apdu.getOffsetCdata(), tempBufferRam, offset, len);
        offset += len;

        while (len > 0) {
            len = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
            Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, tempBufferRam, offset, len);
            offset += len;
        }

        if (offset < (short) 320) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        AESKey mk = secManager.getMasterKey();
        short readOff = 0;

        repository.write(Constants.OFF_CARD_ID, tempBufferRam, readOff, Constants.LEN_CARD_ID, mk);
        readOff += Constants.LEN_CARD_ID;

        repository.write(Constants.OFF_FULLNAME, tempBufferRam, readOff, Constants.LEN_FULLNAME, mk);
        readOff += Constants.LEN_FULLNAME;

        repository.write(Constants.OFF_DOB, tempBufferRam, readOff, Constants.LEN_DOB, mk);
        readOff += Constants.LEN_DOB;

        repository.write(Constants.OFF_PHONE, tempBufferRam, readOff, Constants.LEN_PHONE, mk);
        readOff += Constants.LEN_PHONE;

        repository.write(Constants.OFF_ADDRESS, tempBufferRam, readOff, Constants.LEN_ADDRESS, mk);
        readOff += Constants.LEN_ADDRESS;

        repository.write(Constants.OFF_REG_DATE, tempBufferRam, readOff, Constants.LEN_REG_DATE, mk);
        readOff += Constants.LEN_REG_DATE;

        repository.write(Constants.OFF_APP_PUBLIC_KEY, tempBufferRam, readOff, Constants.LEN_APP_PUBLIC_KEY, mk);

        // --- INIT BALANCE = 0 ---
        Util.arrayFillNonAtomic(tempBufferRam, (short) 0, Constants.LEN_BALANCE, (byte) 0);
        repository.write(Constants.OFF_BALANCE, tempBufferRam, (short) 0, Constants.LEN_BALANCE, mk);

        // --- INIT POINTS = 0 ---
        // tempBufferRam van dang la 0
        repository.write(Constants.OFF_POINTS, tempBufferRam, (short) 0, Constants.LEN_POINTS, mk);

        // --- INIT MEMBER TYPE = 0 ---
        // Van dung tempBufferRam dang chua toan 0
        repository.write(Constants.OFF_MEMBER_TYPE, tempBufferRam, (short) 0, Constants.LEN_MEMBER_TYPE, mk);

        // --- INIT BORROW DATA (240 bytes = 0) ---
        // tempBufferRam (512 bytes) dang chua toan 0 (do da fill o tren hoac mac dinh)
        // De chac chan, ta fill lai 240 bytes
        Util.arrayFillNonAtomic(tempBufferRam, (short) 0, Constants.LEN_BORROW_DATA, (byte) 0);
        repository.write(Constants.OFF_BORROW_DATA, tempBufferRam, (short) 0, Constants.LEN_BORROW_DATA, mk);

        // --- NEW: SET FIRST LOGIN FLAG ---
        secManager.setFirstLogin(true);
    }

    private void handleUpdateInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        // Expect: Name (64) + DOB (16) + Phone (16) + Address (64) = 160 bytes
        short len = apdu.setIncomingAndReceive();

        // Copy vao RAM truoc de xu ly
        short offset = 0;
        Util.arrayCopy(buffer, apdu.getOffsetCdata(), tempBufferRam, offset, len);
        offset += len;

        // Neu du lieu bi cat (chaining), doc not
        while (len > 0 && offset < 160) {
            len = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
            Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, tempBufferRam, offset, len);
            offset += len;
        }

        if (offset != 160) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short readOff = 0;

        // 1. Update Name
        repository.write(Constants.OFF_FULLNAME, tempBufferRam, readOff, Constants.LEN_FULLNAME, mk);
        readOff += Constants.LEN_FULLNAME;

        // 2. Update DOB
        repository.write(Constants.OFF_DOB, tempBufferRam, readOff, Constants.LEN_DOB, mk);
        readOff += Constants.LEN_DOB;

        // 3. Update Phone
        repository.write(Constants.OFF_PHONE, tempBufferRam, readOff, Constants.LEN_PHONE, mk);
        readOff += Constants.LEN_PHONE;

        // 4. Update Address
        repository.write(Constants.OFF_ADDRESS, tempBufferRam, readOff, Constants.LEN_ADDRESS, mk);
        readOff += Constants.LEN_ADDRESS;
    }

    private void handleAuthGetCardId(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        apdu.setOutgoing();
        apdu.setOutgoingLength(Constants.LEN_CARD_ID);

        repository.read(Constants.OFF_CARD_ID, Constants.LEN_CARD_ID, buffer, (short) 0, mk);

        apdu.sendBytes((short) 0, Constants.LEN_CARD_ID);
    }

    private void handleAuthChallenge(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        short sigLen = secManager.signData(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, sigLen);
    }

    private void handleGetPinTries(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte tries = secManager.getPinTries();
        buffer[0] = tries;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    private void handleGetInfoSecure(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        apdu.setOutgoing();
        // Cu: 192 bytes. Moi: 192 + 1 (MemberType) = 193 bytes
        apdu.setOutgoingLength((short) 193);

        short plainOff = 0;

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

        // --- READ MEMBER TYPE ---
        // Doc 16 bytes vao tempBufferRam (de decrypt dung block)
        repository.read(Constants.OFF_MEMBER_TYPE, Constants.LEN_MEMBER_TYPE, tempBufferRam, (short) 0, mk);
        // Copy 1 byte dau tien vao buffer output
        buffer[(short) 192] = tempBufferRam[0];

        apdu.sendBytes((short) 0, (short) 193);
    }

    private void handleAddPoint(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        // 1. Nhan so diem cong (4 bytes)
        short len = apdu.setIncomingAndReceive();
        if (len != 4)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // 2. Doc Points hien tai -> tempBufferRam
        repository.read(Constants.OFF_POINTS, Constants.LEN_POINTS, tempBufferRam, (short) 0, mk);

        // 3. Cong diem: tempBufferRam + buffer
        addBigNumber(tempBufferRam, (short) 0, buffer, apdu.getOffsetCdata(), (short) 4);

        // 4. Ghi lai
        repository.write(Constants.OFF_POINTS, tempBufferRam, (short) 0, Constants.LEN_POINTS, mk);
    }

    private void handleUsePoint(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        // 1. Nhan so diem can tru (4 bytes)
        short len = apdu.setIncomingAndReceive();
        if (len != 4)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // 2. Doc Points hien tai -> tempBufferRam
        repository.read(Constants.OFF_POINTS, Constants.LEN_POINTS, tempBufferRam, (short) 0, mk);

        // 3. Kiem tra du diem khong? (Current >= Amount?)
        byte cmp = compareBigNumber(tempBufferRam, (short) 0, buffer, apdu.getOffsetCdata(), (short) 4);

        if (cmp < 0) {
            ISOException.throwIt(Constants.SW_VERIFICATION_FAILED); // Khong du diem
        }

        // 4. Tru diem: tempBufferRam - buffer
        subtractBigNumber(tempBufferRam, (short) 0, buffer, apdu.getOffsetCdata(), (short) 4);

        // 5. Ghi lai
        repository.write(Constants.OFF_POINTS, tempBufferRam, (short) 0, Constants.LEN_POINTS, mk);
    }

    private void handleUpgradeMember(APDU apdu, byte newType) {
        AESKey mk = secManager.getMasterKey();

        // Chuan bi data: 1 byte type + 15 bytes 0 padding
        Util.arrayFillNonAtomic(tempBufferRam, (short) 0, Constants.LEN_MEMBER_TYPE, (byte) 0);
        tempBufferRam[0] = newType;

        // Ghi vao EEPROM
        repository.write(Constants.OFF_MEMBER_TYPE, tempBufferRam, (short) 0, Constants.LEN_MEMBER_TYPE, mk);
    }

    // --- BORROW BOOK HANDLERS ---

    private void handleBorrowBook(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        // 1. Nhan 16 bytes (7 ID + 8 Date + 1 Duration)
        short len = apdu.setIncomingAndReceive();
        if (len != 16)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // 2. Doc toan bo Borrow Data (240 bytes) vao RAM
        repository.read(Constants.OFF_BORROW_DATA, Constants.LEN_BORROW_DATA, tempBufferRam, (short) 0, mk);

        // 3. Tim slot trong va Kiem tra trung ID
        short freeSlotOffset = -1;
        short slotSize = Constants.LEN_BOOK_SLOT; // 16

        // Input Book ID nam o buffer[ISO7816.OFFSET_CDATA] (7 bytes)
        short inputIdOffset = ISO7816.OFFSET_CDATA;

        for (short i = 0; i < Constants.MAX_BORROWED_BOOKS; i++) {
            short currentOffset = (short) (i * slotSize);

            // Kiem tra slot co du lieu khong (Byte dau tien khac 0 la co data)
            boolean isSlotUsed = false;
            for (short j = 0; j < 7; j++) {
                if (tempBufferRam[(short) (currentOffset + j)] != 0) {
                    isSlotUsed = true;
                    break;
                }
            }

            if (isSlotUsed) {
                // Check ID duplicate
                if (Util.arrayCompare(tempBufferRam, currentOffset, buffer, inputIdOffset, (short) 6) == 0) {
                    ISOException.throwIt(Constants.SW_VERIFICATION_FAILED); // Da muon roi
                }
            } else {
                // Day la slot trong dau tien tim thay
                if (freeSlotOffset == -1) {
                    freeSlotOffset = currentOffset;
                }
            }
        }

        if (freeSlotOffset == -1) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL); // Het cho
        }

        // 4. Ghi data vao slot trong tim duoc tren RAM
        Util.arrayCopy(buffer, inputIdOffset, tempBufferRam, freeSlotOffset, (short) 16);

        // 5. Ghi nguoc RAM xuong EEPROM
        repository.write(Constants.OFF_BORROW_DATA, tempBufferRam, (short) 0, Constants.LEN_BORROW_DATA, mk);
    }

    private void handleReturnBook(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        // 1. Nhan Book ID (6 bytes)
        short len = apdu.setIncomingAndReceive();
        // Client co the gui 6 bytes hoac padding len 16 bytes deu duoc, ta chi lay 6
        // bytes dau
        if (len < 6)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // 2. Doc data vao RAM
        repository.read(Constants.OFF_BORROW_DATA, Constants.LEN_BORROW_DATA, tempBufferRam, (short) 0, mk);

        // 3. Tim sach can tra
        short targetOffset = -1;
        short slotSize = Constants.LEN_BOOK_SLOT;
        short inputIdOffset = ISO7816.OFFSET_CDATA;

        for (short i = 0; i < Constants.MAX_BORROWED_BOOKS; i++) {
            short currentOffset = (short) (i * slotSize);

            // So sanh 6 bytes ID
            if (Util.arrayCompare(tempBufferRam, currentOffset, buffer, inputIdOffset, (short) 6) == 0) {
                targetOffset = currentOffset;
                break;
            }
        }

        if (targetOffset == -1) {
            ISOException.throwIt(Constants.SW_VERIFICATION_FAILED); // Khong tim thay sach
        }

        // 4. Xoa slot (Ghi de = 0)
        Util.arrayFillNonAtomic(tempBufferRam, targetOffset, slotSize, (byte) 0);

        // 5. Update EEPROM
        repository.write(Constants.OFF_BORROW_DATA, tempBufferRam, (short) 0, Constants.LEN_BORROW_DATA, mk);
    }

    private void handleGetBorrowedBooks(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        apdu.setOutgoing();
        apdu.setOutgoingLength(Constants.LEN_BORROW_DATA); // 240 bytes

        // Doc data vao buffer
        repository.read(Constants.OFF_BORROW_DATA, Constants.LEN_BORROW_DATA, buffer, (short) 0, mk);

        // Gui ve client
        apdu.sendBytes((short) 0, Constants.LEN_BORROW_DATA);
    }

    private void handleUploadImage(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        short len = apdu.setIncomingAndReceive();
        short dataOffset = apdu.getOffsetCdata();

        short currentImageOffset = 0;
        short ramOffset = 0;
        short CHUNK_SIZE = 256; // Must match Client Read size

        // Initial copy to RAM buffer
        Util.arrayCopy(buffer, dataOffset, tempBufferRam, ramOffset, len);
        ramOffset += len;

        // Loop to process chunks
        while (len > 0) {
            // While we have enough data for a full chunk
            while (ramOffset >= CHUNK_SIZE) {
                // Write exactly CHUNK_SIZE to EEPROM
                repository.write((short) (Constants.OFF_IMAGE + currentImageOffset),
                        tempBufferRam, (short) 0, CHUNK_SIZE, mk);
                currentImageOffset += CHUNK_SIZE;

                // Shift remaining data to start of buffer
                ramOffset -= CHUNK_SIZE;
                if (ramOffset > 0) {
                    Util.arrayCopy(tempBufferRam, CHUNK_SIZE, tempBufferRam, (short) 0, ramOffset);
                }
            }

            // Receive next batch
            len = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
            if (len > 0) {
                // Check overflow (optional but safe)
                if ((short) (ramOffset + len) > (short) tempBufferRam.length) {
                    ISOException.throwIt(ISO7816.SW_FILE_FULL);
                }
                Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, tempBufferRam, ramOffset, len);
                ramOffset += len;
            }
        }

        // Write remaining data (if any)
        if (ramOffset > 0) {
            repository.write((short) (Constants.OFF_IMAGE + currentImageOffset),
                    tempBufferRam, (short) 0, ramOffset, mk);
        }
    }

    // --- MODIFIED: GET IMAGE (CHUNKED) ---
    private void handleGetImage(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        // Lay offset tu P1 P2
        short p1 = (short) (buffer[ISO7816.OFFSET_P1] & 0xFF);
        short p2 = (short) (buffer[ISO7816.OFFSET_P2] & 0xFF);
        short offset = (short) ((p1 << 8) | p2);

        if (offset < 0 || offset >= Constants.LEN_IMAGE) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Xac dinh do dai muon doc (Client gui trong Le, hoac mac dinh)
        short len = apdu.setOutgoing();

        // Cat bot neu vuot qua kich thuoc anh
        if ((short) (offset + len) > Constants.LEN_IMAGE) {
            len = (short) (Constants.LEN_IMAGE - offset);
        }

        apdu.setOutgoingLength(len);

        // Doc chunk tu EEPROM
        repository.read((short) (Constants.OFF_IMAGE + offset), len, buffer, (short) 0, mk);

        // Gui chunk
        apdu.sendBytes((short) 0, len);
    }

    // --- BALANCE METHODS ---

    private void handleGetBalance(APDU apdu) {
        // Can verify PIN neu can thiet (o day cho phep doc thoai mai de hien thi)
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 8); // Client can 4 bytes Balance + 4 bytes Points

        // 1. Doc Balance (16 bytes) -> buffer[0..3]
        repository.read(Constants.OFF_BALANCE, Constants.LEN_BALANCE, tempBufferRam, (short) 0, mk);
        Util.arrayCopy(tempBufferRam, (short) 0, buffer, (short) 0, (short) 4);

        // 2. Doc Points (16 bytes) -> buffer[4..7]
        repository.read(Constants.OFF_POINTS, Constants.LEN_POINTS, tempBufferRam, (short) 0, mk);
        Util.arrayCopy(tempBufferRam, (short) 0, buffer, (short) 4, (short) 4);

        // Gui 8 bytes
        apdu.sendBytes((short) 0, (short) 8);
    }

    private void handleDeposit(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        // 1. Nhan so tien nap (4 bytes)
        short len = apdu.setIncomingAndReceive();
        if (len != 4)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // 2. Doc so du hien tai -> tempBufferRam[0..3]
        repository.read(Constants.OFF_BALANCE, Constants.LEN_BALANCE, tempBufferRam, (short) 0, mk);

        // 3. Cong tien
        addBigNumber(tempBufferRam, (short) 0, buffer, apdu.getOffsetCdata(), (short) 4);

        // 4. Ghi lai so du moi (NO TRANSACTION - Repository tu lo)
        repository.write(Constants.OFF_BALANCE, tempBufferRam, (short) 0, Constants.LEN_BALANCE, mk);
    }

    private void handlePayment(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        AESKey mk = secManager.getMasterKey();

        // 1. Nhan so tien thanh toan (4 bytes)
        short len = apdu.setIncomingAndReceive();
        if (len != 4)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // 2. Doc so du hien tai -> tempBufferRam[0..3]
        repository.read(Constants.OFF_BALANCE, Constants.LEN_BALANCE, tempBufferRam, (short) 0, mk);

        // 3. Kiem tra so du (Current >= Payment?)
        byte cmp = compareBigNumber(tempBufferRam, (short) 0, buffer, apdu.getOffsetCdata(), (short) 4);

        if (cmp < 0) {
            ISOException.throwIt(Constants.SW_VERIFICATION_FAILED);
        }

        // 4. Tru tien: tempBufferRam - buffer
        subtractBigNumber(tempBufferRam, (short) 0, buffer, apdu.getOffsetCdata(), (short) 4);

        // 5. Ghi lai
        repository.write(Constants.OFF_BALANCE, tempBufferRam, (short) 0, Constants.LEN_BALANCE, mk);
    }

    // --- BIG NUMBER HELPERS (4 Bytes / Generic) ---

    // Cong: dest = dest + src
    private void addBigNumber(byte[] dest, short destOff, byte[] src, short srcOff, short len) {
        short carry = 0;
        for (short i = (short) (len - 1); i >= 0; i--) {
            short sum = (short) ((dest[(short) (destOff + i)] & 0xFF) + (src[(short) (srcOff + i)] & 0xFF) + carry);
            dest[(short) (destOff + i)] = (byte) sum;
            carry = (short) (sum >> 8);
        }
    }

    // Tru: dest = dest - src (Gia su dest >= src)
    private void subtractBigNumber(byte[] dest, short destOff, byte[] src, short srcOff, short len) {
        short borrow = 0;
        for (short i = (short) (len - 1); i >= 0; i--) {
            short sub = (short) ((dest[(short) (destOff + i)] & 0xFF) - (src[(short) (srcOff + i)] & 0xFF) - borrow);
            if (sub < 0) {
                sub += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            dest[(short) (destOff + i)] = (byte) sub;
        }
    }

    // So sanh: tra ve 1 (l>r), -1 (l<r), 0 (l=r)
    private byte compareBigNumber(byte[] left, short leftOff, byte[] right, short rightOff, short len) {
        for (short i = 0; i < len; i++) {
            short l = (short) (left[(short) (leftOff + i)] & 0xFF);
            short r = (short) (right[(short) (rightOff + i)] & 0xFF);
            if (l < r)
                return -1;
            if (l > r)
                return 1;
        }
        return 0;
    }
    // --- FIRST TIME LOGIN HANDLERS ---

    private void handleCheckFirstLogin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = secManager.isFirstLogin() ? (byte) 1 : (byte) 0;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    private void handleDisableFirstLogin(APDU apdu) {
        // Can be protected by PIN if needed, but per requirement just disable
        secManager.setFirstLogin(false);
    }
}
