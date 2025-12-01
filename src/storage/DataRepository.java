package storage;

import javacard.framework.*;
import javacardx.crypto.*;
import javacard.security.*;
import common.Constants;

public class DataRepository {
    
    private byte[] dataBlob; // Mang lon chua tat ca info (Encrypted)
    private Cipher aesCipher;
    private byte[] ivBuffer; // Buffer cho IV
    private byte[] tempBlock; // Buffer cho padding (16 bytes)
    
    public DataRepository() {
        dataBlob = new byte[Constants.DATA_SIZE];
        aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        ivBuffer = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
        tempBlock = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
    }

    // Helper de tao IV tu offset (Dung offset lam IV de tranh trung lap Pattern)
    private void generateIv(short offset) {
        Util.arrayFillNonAtomic(ivBuffer, (short) 0, (short) 16, (byte) 0);
        // Ghi offset vao cuoi IV (Big Endian)
        ivBuffer[14] = (byte) (offset >> 8);
        ivBuffer[15] = (byte) (offset & 0xFF);
    }

    // Ghi du lieu (App gui Plaintext -> The encrypt -> Luu)
    public void write(short offset, byte[] input, short inOff, short len, AESKey masterKey) {
        // Luu y: AES CBC can du lieu dau vao chia het cho 16 bytes (Padding).
        // Neu len khong chia het cho 16, tu dong pad 0.

        JCSystem.beginTransaction();
        try {
            generateIv(offset);
            aesCipher.init(masterKey, Cipher.MODE_ENCRYPT, ivBuffer, (short) 0, (short) 16);

            short remainder = (short) (len % 16);
            short mainLen = (short) (len - remainder);

            if (remainder == 0) {
                // Truong hop dep: Chia het cho 16 -> Ghi thang
        aesCipher.doFinal(input, inOff, len, dataBlob, offset);
            } else {
                // Truong hop le: Encrypt phan chan truoc
                if (mainLen > 0) {
                    aesCipher.update(input, inOff, mainLen, dataBlob, offset);
    }
    
                // Xu ly phan le: Copy ra tempBlock va pad 0
                Util.arrayCopy(input, (short) (inOff + mainLen), tempBlock, (short) 0, remainder);
                Util.arrayFillNonAtomic(tempBlock, remainder, (short) (16 - remainder), (byte) 0);

                // Encrypt block cuoi cung (16 bytes)
                aesCipher.doFinal(tempBlock, (short) 0, (short) 16, dataBlob, (short) (offset + mainLen));
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            // ISOException.throwIt(ISO7816.SW_UNKNOWN);
            // Throw loi ro rang hon de debug neu can
             ISOException.throwIt((short)0x6F00); 
        }
    }

    // Doc du lieu (Lay Encrypted tu Blob -> Decrypt -> Tra ve Plaintext)
    public void read(short offset, short len, byte[] output, short outOff, AESKey masterKey) {
        generateIv(offset);
        aesCipher.init(masterKey, Cipher.MODE_DECRYPT, ivBuffer, (short) 0, (short) 16);
        // Giai ma tu dataBlob ra output buffer
        aesCipher.doFinal(dataBlob, offset, len, output, outOff);
    }
}
