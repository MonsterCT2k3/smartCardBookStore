package storage;

import javacard.framework.*;
import javacardx.crypto.*;
import javacard.security.*;
import common.Constants;

public class DataRepository {

    // --- CAC TRUONG DU LIEU RIENG BIET (EEPROM) ---
    private byte[] cardId;
    private byte[] fullName;
    private byte[] dob;
    private byte[] phone;
    private byte[] address;
    private byte[] regDate;
    private byte[] appPublicKey;
    private byte[] balance;
    private byte[] points;
    private byte[] memberType;
    private byte[] borrowData;
    private byte[] image;

    private Cipher aesCipher;
    private byte[] ivBuffer; // Bo dem cho IV (Transient)
    private byte[] tempBlock; // Bo dem cho padding (Transient)

    public DataRepository() {
        // Khoi tao tung mang voi do dai co dinh tu Constants
        cardId = new byte[Constants.LEN_CARD_ID];
        fullName = new byte[Constants.LEN_FULLNAME];
        dob = new byte[Constants.LEN_DOB];
        phone = new byte[Constants.LEN_PHONE];
        address = new byte[Constants.LEN_ADDRESS];
        regDate = new byte[Constants.LEN_REG_DATE];
        appPublicKey = new byte[Constants.LEN_APP_PUBLIC_KEY];
        balance = new byte[Constants.LEN_BALANCE];
        points = new byte[Constants.LEN_POINTS];
        memberType = new byte[Constants.LEN_MEMBER_TYPE];
        borrowData = new byte[Constants.LEN_BORROW_DATA];
        image = new byte[Constants.LEN_IMAGE];

        aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        ivBuffer = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
        tempBlock = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
    }

    // Helper tao IV dua tren Tag cua truong du lieu de dam bao tinh duy nhat
    private void generateIv(short tag) {
        Util.arrayFillNonAtomic(ivBuffer, (short) 0, (short) 16, (byte) 0);
        // Ghi tag vao cuoi IV
        ivBuffer[14] = (byte) (tag >> 8);
        ivBuffer[15] = (byte) (tag & 0xFF);
    }

    // Ham ghi du lieu tong quat cho mot mang cu the (Co ma hoa AES)
    private void writeField(byte[] storage, short tag, byte[] input, short inOff, short len, AESKey masterKey) {
        // Gioi han len khong vuot qua kich thuoc mang luu tru
        if (len > (short) storage.length) {
            len = (short) storage.length;
        }

        JCSystem.beginTransaction();
        try {
            generateIv(tag);
            aesCipher.init(masterKey, Cipher.MODE_ENCRYPT, ivBuffer, (short) 0, (short) 16);

            short remainder = (short) (len % 16);
            short mainLen = (short) (len - remainder);

            if (remainder == 0) {
                // Truong hop dep: Chia het cho 16 -> Ghi thang
                aesCipher.doFinal(input, inOff, len, storage, (short) 0);
            } else {
                // Truong hop le: Encrypt phan chan truoc
                if (mainLen > 0) {
                    aesCipher.update(input, inOff, mainLen, storage, (short) 0);
                }

                // Xu ly phan le: Copy ra tempBlock va pad 0
                Util.arrayCopyNonAtomic(input, (short) (inOff + mainLen), tempBlock, (short) 0, remainder);
                Util.arrayFillNonAtomic(tempBlock, remainder, (short) (16 - remainder), (byte) 0);

                // Encrypt block cuoi cung (16 bytes)
                aesCipher.doFinal(tempBlock, (short) 0, (short) 16, storage, mainLen);
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt((short) 0x6F01);
        }
    }

    // Ham doc du lieu tong quat (Co giai ma AES)
    private void readField(byte[] storage, short tag, byte[] output, short outOff, AESKey masterKey) {
        generateIv(tag);
        aesCipher.init(masterKey, Cipher.MODE_DECRYPT, ivBuffer, (short) 0, (short) 16);
        // Giai ma tu mang storage ra output buffer
        aesCipher.doFinal(storage, (short) 0, (short) storage.length, output, outOff);
    }

    // --- CAC HAM TRUY XUAT CU THE CHO TUNG TRUONG ---

    public void writeCardId(byte[] in, short off, AESKey k) {
        writeField(cardId, (short) 1, in, off, Constants.LEN_CARD_ID, k);
    }

    public void readCardId(byte[] out, short off, AESKey k) {
        readField(cardId, (short) 1, out, off, k);
    }

    public void writeFullName(byte[] in, short off, AESKey k) {
        writeField(fullName, (short) 2, in, off, Constants.LEN_FULLNAME, k);
    }

    public void readFullName(byte[] out, short off, AESKey k) {
        readField(fullName, (short) 2, out, off, k);
    }

    public void writeDob(byte[] in, short off, AESKey k) {
        writeField(dob, (short) 3, in, off, Constants.LEN_DOB, k);
    }

    public void readDob(byte[] out, short off, AESKey k) {
        readField(dob, (short) 3, out, off, k);
    }

    public void writePhone(byte[] in, short off, AESKey k) {
        writeField(phone, (short) 4, in, off, Constants.LEN_PHONE, k);
    }

    public void readPhone(byte[] out, short off, AESKey k) {
        readField(phone, (short) 4, out, off, k);
    }

    public void writeAddress(byte[] in, short off, AESKey k) {
        writeField(address, (short) 5, in, off, Constants.LEN_ADDRESS, k);
    }

    public void readAddress(byte[] out, short off, AESKey k) {
        readField(address, (short) 5, out, off, k);
    }

    public void writeRegDate(byte[] in, short off, AESKey k) {
        writeField(regDate, (short) 6, in, off, Constants.LEN_REG_DATE, k);
    }

    public void readRegDate(byte[] out, short off, AESKey k) {
        readField(regDate, (short) 6, out, off, k);
    }

    public void writeBalance(byte[] in, short off, AESKey k) {
        writeField(balance, (short) 8, in, off, Constants.LEN_BALANCE, k);
    }

    public void readBalance(byte[] out, short off, AESKey k) {
        readField(balance, (short) 8, out, off, k);
    }

    public void writePoints(byte[] in, short off, AESKey k) {
        writeField(points, (short) 9, in, off, Constants.LEN_POINTS, k);
    }

    public void readPoints(byte[] out, short off, AESKey k) {
        readField(points, (short) 9, out, off, k);
    }

    public void writeMemberType(byte[] in, short off, AESKey k) {
        writeField(memberType, (short) 10, in, off, Constants.LEN_MEMBER_TYPE, k);
    }

    public void readMemberType(byte[] out, short off, AESKey k) {
        readField(memberType, (short) 10, out, off, k);
    }

    public void writeBorrowData(byte[] in, short off, AESKey k) {
        writeField(borrowData, (short) 11, in, off, Constants.LEN_BORROW_DATA, k);
    }

    public void readBorrowData(byte[] out, short off, AESKey k) {
        readField(borrowData, (short) 11, out, off, k);
    }

    public void writeImageChunk(short imageOffset, byte[] in, short off, short len, AESKey k) {
        // Ghi de truc tiep vao mang image tai vi tri imageOffset (Can quan ly
        // Transaction ben ngoai neu ghi nhieu chunks)
        // Luu y: De don gian, ta van dung writeField nhung cho phep offset noi bo
        if ((short) (imageOffset + len) > Constants.LEN_IMAGE)
            len = (short) (Constants.LEN_IMAGE - imageOffset);

        generateIv((short) (12 + imageOffset / 16)); // IV thay doi theo block
        aesCipher.init(k, Cipher.MODE_ENCRYPT, ivBuffer, (short) 0, (short) 16);

        // Gia su len chia het cho 16 vi image thuong duoc ghi theo chunks 256 bytes
        aesCipher.doFinal(in, off, len, image, imageOffset);
    }

    public void readImageChunk(short imageOffset, short len, byte[] out, short off, AESKey k) {
        if ((short) (imageOffset + len) > Constants.LEN_IMAGE)
            len = (short) (Constants.LEN_IMAGE - imageOffset);

        generateIv((short) (12 + imageOffset / 16));
        aesCipher.init(k, Cipher.MODE_DECRYPT, ivBuffer, (short) 0, (short) 16);
        aesCipher.doFinal(image, imageOffset, len, out, off);
    }

    // App Public Key (Khong ma hoa de tien handshake)
    public void writeAppPublicKey(byte[] in, short off) {
        Util.arrayCopy(in, off, appPublicKey, (short) 0, Constants.LEN_APP_PUBLIC_KEY);
    }

    public void readAppPublicKey(byte[] out, short off) {
        Util.arrayCopy(appPublicKey, (short) 0, out, off, Constants.LEN_APP_PUBLIC_KEY);
    }
}
