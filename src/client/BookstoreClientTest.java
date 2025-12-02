package client;

import javax.smartcardio.*;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class BookstoreClientTest {

    // --- APDU INS Constants ---
    private static final byte INS_SETUP_CARD = (byte) 0x10;
    private static final byte INS_INIT_DATA = (byte) 0x15;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0x22;
    private static final byte INS_AUTH_GET_CARD_ID = (byte) 0x31; // Auth Step 1
    private static final byte INS_AUTH_CHALLENGE = (byte) 0x32; // Auth Step 2: Challenge-Response
    private static final byte INS_CHANGE_PIN = (byte) 0x25; // Change PIN
    private static final byte INS_UNBLOCK_PIN = (byte) 0x26; // Unblock PIN
    private static final byte INS_GET_PIN_TRIES = (byte) 0x33; // Get PIN Tries
    private static final byte INS_RESET_PIN = (byte) 0x50;
    private static final byte INS_GET_INFO = (byte) 0x30;

    // --- HARDCODED TEST DATA ---
    private static final String DATA_USER_PIN = "123456";
    private static final String DATA_ADMIN_PIN = "ABCDEF";
    private static final String DATA_NEW_PIN = "654321";

    private static final String DATA_CARD_ID = "SV00123456";
    private static final String DATA_NAME = "Nguyen Van A";
    private static final String DATA_DOB = "01011999";
    private static final String DATA_PHONE = "0987654321";
    private static final String DATA_ADDRESS = "144 Xuan Thuy, Cau Giay, HN";
    private static final String DATA_REG_DATE = "30112025";

    // --- State Variables ---
    private static CardChannel channel = null;
    private static PublicKey cardPublicKey = null;
    private static KeyPair appKeyPair = null; // App's RSA KeyPair
    private static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        // Tu dong ket noi luon khi chay
        try {
            connectCard();
        } catch (Exception e) {
            System.err.println("Auto-connect failed: " + e.getMessage());
        }

        while (true) {
            System.out.println("\n==========================================");
            System.out.println("    BOOKSTORE CARD TEST (EXTENDED APDU)");
            System.out.println("==========================================");
            System.out.println("1. Connect & Select Applet");
            System.out.println("2. Get Card Public Key");
            System.out.println("3. Setup Card (PIN: " + DATA_USER_PIN + ")");
            System.out.println("4. Verify User PIN");
            System.out.println("5. Init All Data (Text + App PubKey)");
            System.out.println("6. Get User Info (PLAINTEXT)");
            System.out.println("7. Reset User PIN");
            System.out.println("8. Change PIN (User)");
            System.out.println("9. Authenticate Card (Challenge-Response)");
            System.out.println("10. Unblock Card (Admin Only)");
            System.out.println("11. Get PIN Tries");
            System.out.println("0. Exit");
            System.out.print("Choose option: ");

            String choice = scanner.nextLine();

            try {
                switch (choice) {
                    case "1":
                        connectCard();
                        break;
                    case "2":
                        getPublicKey();
                        break;
                    case "3":
                        setupCard();
                        break;
                    case "4":
                        verifyPin();
                        break;
                    case "5":
                        initUserDataExtended();
                        break;
                    case "6":
                        getInfo();
                        break;
                    case "7":
                        resetUserPin();
                        break;
                    case "8":
                        changePin();
                        break;
                    case "9":
                        authenticateUser();
                        break;
                    case "10":
                        unblockCard();
                        break;
                    case "11":
                        getPinTries();
                        break;
                    case "0":
                        System.out.println("Exiting...");
                        return;
                    default:
                        System.out.println("Invalid option!");
                }
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                // e.printStackTrace();
            }
        }
    }

    // --- FUNCTIONAL METHODS ---

    private static void connectCard() throws Exception {
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();

        if (terminals.isEmpty()) {
            throw new Exception("No card terminals found!");
        }

        System.out.println("Terminals found: " + terminals.size());
        CardTerminal terminal = terminals.get(0);
        System.out.println("Connecting to: " + terminal.getName());

        // FIX: Try connecting with T=1 for Extended APDU support
        Card card = null;
        try {
            card = terminal.connect("T=1");
            System.out.println("Connected with protocol: T=1 (Extended APDU Supported)");
        } catch (CardException e) {
            System.out.println("Warning: T=1 not supported, falling back to * (T=0 might fail with Extended APDU)");
            card = terminal.connect("*");
        }

        channel = card.getBasicChannel();

        byte[] aid = hexStringToByteArray("11223344550300");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid));
        System.out.println("Select Applet: " + Integer.toHexString(r.getSW()));

        if (r.getSW() != 0x9000) {
            channel = null;
            throw new Exception("Select Applet Failed. SW: " + Integer.toHexString(r.getSW()));
        }
        System.out.println(">>> Connected successfully!");
    }

    private static void getPublicKey() throws Exception {
        checkConnection();
        System.out.println("Fetching Public Key from Card...");
        cardPublicKey = fetchCardPublicKey(channel);
        System.out.println(">>> Got Public Key successfully.");

        // Dong thoi sinh RSA Key cho App (neu chua co)
        if (appKeyPair == null) {
            System.out.println("Generating App's RSA KeyPair...");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            appKeyPair = keyGen.generateKeyPair();
            System.out.println(">>> App KeyPair generated.");
        }
    }

    private static void setupCard() throws Exception {
        checkConnection();
        checkPublicKey();

        System.out.println("Sending Setup Data (Hardcoded)...");

        byte[] setupData = new byte[12];
        System.arraycopy(DATA_USER_PIN.getBytes(), 0, setupData, 0, 6);
        System.arraycopy(DATA_ADMIN_PIN.getBytes(), 0, setupData, 6, 6);

        // --- FIX: Send as PLAINTEXT, not Secure Command ---
        System.out.println("Sending Setup Data (PLAINTEXT)...");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_SETUP_CARD, 0x00, 0x00, setupData));

        System.out.println("Response SW: " + Integer.toHexString(r.getSW()));
        if (r.getSW() == 0x9000) {
            System.out.println(">>> SUCCESS");
        } else {
            System.out.println(">>> FAILED");
        }
    }

    private static void verifyPin() throws Exception {
        checkConnection();
        checkPublicKey();
        System.out.println("Enter User PIN to Verify: ");

        String userPin = scanner.nextLine();

        System.out.println("Verifying PIN: " + userPin + " (PLAINTEXT)");

        // --- FIX: Send PIN as PLAINTEXT ---
        byte[] pinData = userPin.getBytes();
        // Co the padding 0 neu can, nhung o day truyen raw

        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_VERIFY_PIN, 0x00, 0x00, pinData));

        System.out.println("Response SW: " + Integer.toHexString(r.getSW()));
        if (r.getSW() == 0x9000) {
            System.out.println(">>> LOGIN SUCCESS");
        } else {
            System.out.println(">>> LOGIN FAILED");
        }
    }

    private static void initUserDataExtended() throws Exception {
        checkConnection();

        if (appKeyPair == null) {
            System.out.println("Error: App KeyPair not generated. Please run option 2 first.");
            return;
        }

        System.out.println("Initializing Data (Text + App PublicKey)...");
        System.out.println("Name: " + DATA_NAME);
        System.out.println("Phone: " + DATA_PHONE);
        System.out.println("Address: " + DATA_ADDRESS);

        // Prepare Payload: 192 Text + 128 AppPubKey = 320 bytes
        byte[] payload = new byte[320];
        int offset = 0;

        // 1. Text Data (192 bytes)
        // CardID (16)
        System.arraycopy(createFixedLengthData(DATA_CARD_ID, 16), 0, payload, offset, 16);
        offset += 16;
        // Name (64)
        System.arraycopy(createFixedLengthData(DATA_NAME, 64), 0, payload, offset, 64);
        offset += 64;
        // DOB (16)
        System.arraycopy(createFixedLengthData(DATA_DOB, 16), 0, payload, offset, 16);
        offset += 16;
        // Phone (16)
        System.arraycopy(createFixedLengthData(DATA_PHONE, 16), 0, payload, offset, 16);
        offset += 16;
        // Address (64)
        System.arraycopy(createFixedLengthData(DATA_ADDRESS, 64), 0, payload, offset, 64);
        offset += 64;
        // RegDate (16)
        System.arraycopy(createFixedLengthData(DATA_REG_DATE, 16), 0, payload, offset, 16);
        offset += 16;

        // 2. App Public Key (Modulus 128 bytes)
        java.security.interfaces.RSAPublicKey rsaPubKey = (java.security.interfaces.RSAPublicKey) appKeyPair
                .getPublic();
        byte[] modulus = rsaPubKey.getModulus().toByteArray();

        // BigInteger.toByteArray() co the tra ve 129 bytes (co them byte dau 0x00)
        // Can cat bo byte 0x00 neu co
        byte[] modulusFixed = new byte[128];
        if (modulus.length == 129 && modulus[0] == 0) {
            System.arraycopy(modulus, 1, modulusFixed, 0, 128);
        } else if (modulus.length == 128) {
            System.arraycopy(modulus, 0, modulusFixed, 0, 128);
        } else {
            // Pad 0 vao dau neu modulus < 128 bytes
            int padLen = 128 - modulus.length;
            System.arraycopy(modulus, 0, modulusFixed, padLen, modulus.length);
        }

        System.arraycopy(modulusFixed, 0, payload, offset, 128);

        System.out.println("Total Payload Size: " + payload.length + " bytes");
        System.out.println("Sending APDU...");

        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_INIT_DATA, 0x00, 0x00, payload));

        System.out.println("Response SW: " + Integer.toHexString(r.getSW()));
        if (r.getSW() == 0x9000) {
            System.out.println(">>> SUCCESS: Data & App PubKey Initialized.");
        } else {
            System.out.println(">>> FAILED.");
        }
    }

    private static void getInfo() throws Exception {
        checkConnection();

        if (appKeyPair == null) {
            System.out.println("Error: App KeyPair not available. Please run option 2 first.");
            // return; // Van cho chay tiep vi gio khong dung Hybrid nua
        }

        System.out.println("Getting Info from Card (PLAINTEXT)...");

        // Gui lenh GET_INFO
        // Le = 192 (Chi Data, bo RSA Block)
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_GET_INFO, 0x00, 0x00, 192));

        if (r.getSW() != 0x9000) {
            System.out.println("Failed. SW: " + Integer.toHexString(r.getSW()));
            return;
        }

        byte[] plainData = r.getData();
        System.out.println("Received Data Len: " + plainData.length);

        if (plainData.length < 192) {
            System.out.println("Error: Not enough data received.");
            return;
        }

        // --- KHONG CAN GIAI MA HYBRID ---
        // Parse truc tiep tu plainData

        // Structure: [CardID 16] [Name 64] [DOB 16] [Phone 16] [Address 64] [RegDate
        // 16]
        int offset = 0;
        String cardId = new String(Arrays.copyOfRange(plainData, offset, offset + 16)).trim();
        offset += 16;

        String name = new String(Arrays.copyOfRange(plainData, offset, offset + 64)).trim();
        offset += 64;

        String dob = new String(Arrays.copyOfRange(plainData, offset, offset + 16)).trim();
        offset += 16;

        String phone = new String(Arrays.copyOfRange(plainData, offset, offset + 16)).trim();
        offset += 16;

        String address = new String(Arrays.copyOfRange(plainData, offset, offset + 64)).trim();
        offset += 64;

        String regDate = new String(Arrays.copyOfRange(plainData, offset, offset + 16)).trim();

        System.out.println("--- User Info (Decrypted) ---");
        System.out.println("Card ID : " + cardId);
        System.out.println("Name    : " + name);
        System.out.println("DOB     : " + dob);
        System.out.println("Phone   : " + phone);
        System.out.println("Address : " + address);
        System.out.println("RegDate : " + regDate);

        System.out.println("\n(Success!)");
    }

    private static void changePin() throws Exception {
        checkConnection();
        checkPublicKey();

        System.out.println("Changing PIN (User Self-Service)...");
        System.out.print("Enter Old PIN: ");
        String oldPin = scanner.nextLine();
        System.out.print("Enter New PIN: ");
        String newPin = scanner.nextLine();

        if (oldPin.length() != 6 || newPin.length() != 6) {
            System.out.println("Error: PIN must be 6 characters.");
            return;
        }

        byte[] payload = new byte[12];
        System.arraycopy(oldPin.getBytes(), 0, payload, 0, 6);
        System.arraycopy(newPin.getBytes(), 0, payload, 6, 6);

        // --- FIX: Send Plaintext directly ---
        System.out.println("Sending Change PIN Command (PLAINTEXT)...");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_CHANGE_PIN, 0x00, 0x00, payload));

        System.out.println("Response SW: " + Integer.toHexString(r.getSW()));
        if (r.getSW() == 0x9000) {
            System.out.println(">>> CHANGE PIN SUCCESS");
        } else {
            System.out.println(">>> CHANGE PIN FAILED");
        }
    }

    private static void authenticateUser() throws Exception {
        checkConnection();
        // Can private key de decrypt response (cho buoc 1)
        // Can public key de verify signature (cho buoc 2)
        if (appKeyPair == null) {
            System.out.println("Error: App KeyPair not available. Please run option 2 first.");
            return;
        }
        checkPublicKey(); // Dam bao da co Card Public Key

        System.out.println("\n--- STEP 1: IDENTIFICATION (Get Card ID) ---");

        // --- FIX: Receive PLAINTEXT instead of Hybrid Encrypted ---
        // Expect: 16 bytes CardID (Data length = 16)
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_AUTH_GET_CARD_ID, 0x00, 0x00, 16));
        if (r.getSW() != 0x9000) {
            System.out.println("Failed Step 1. SW: " + Integer.toHexString(r.getSW()));
            return;
        }

        byte[] cardIdBytes = r.getData();
        if (cardIdBytes.length < 16) {
            System.out.println("Error: Invalid response length.");
            return;
        }

        // Truc tiep lay CardID tu response (Plaintext)
        String cardId = new String(cardIdBytes).trim();

        System.out.println(">>> Card ID Claimed: " + cardId);

        System.out.println("\n--- STEP 2: AUTHENTICATION (Challenge-Response) ---");
        // 1. Sinh Random Challenge (32 bytes)
        byte[] challenge = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(challenge);
        System.out.println("Challenge Generated: " + bytesToHex(challenge));

        // 2. Gui Challenge xuong the (INS_AUTH_CHALLENGE)
        // The se dung Private Key ky vao Challenge nay
        System.out.println("Sending Challenge to Card...");
        ResponseAPDU r2 = channel.transmit(new CommandAPDU(0x00, INS_AUTH_CHALLENGE, 0x00, 0x00, challenge));

        if (r2.getSW() != 0x9000) {
            System.out.println("Failed Step 2. SW: " + Integer.toHexString(r2.getSW()));
            return;
        }

        byte[] signature = r2.getData();
        System.out.println("Signature Received: " + bytesToHex(signature));

        // 3. Verify Signature bang Card Public Key
        System.out.println("Verifying Signature using Card Public Key...");
        Signature sig = Signature.getInstance("SHA1withRSA"); // JavaCard ALG_RSA_SHA_PKCS1 thuong tuong duong
        // SHA1withRSA hoac SHA256withRSA tuy phien ban.
        // Thu SHA1withRSA truoc vi nhieu the JavaCard cu mac dinh la SHA1.
        // Tuy nhien, neu SecurityManager dung ALG_RSA_SHA_PKCS1 thi no la SHA-1.
        // Neu muon SHA-256 thi phai la ALG_RSA_SHA_256_PKCS1.
        // Code SecurityManager dang dung:
        // Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false); -> Day la SHA-1!
        // Update: Hay sua SecurityManager thanh SHA-256 cho an toan hon neu the ho tro.
        // Nhung de an toan, client cu thu SHA1withRSA truoc.

        sig.initVerify(cardPublicKey);
        sig.update(challenge);

        boolean isValid = sig.verify(signature);

        if (isValid) {
            System.out.println(">>> AUTHENTICATION SUCCESSFUL! Card is genuine.");
        } else {
            System.out.println(">>> AUTHENTICATION FAILED! Signature invalid.");
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
            sb.append(String.format("%02X", b));
        return sb.toString();
    }

    private static void resetUserPin() throws Exception {
        checkConnection();
        checkPublicKey();

        System.out.println("Resetting PIN using Admin Key...");

        byte[] resetData = new byte[12];
        System.arraycopy(DATA_ADMIN_PIN.getBytes(), 0, resetData, 0, 6);
        System.arraycopy(DATA_NEW_PIN.getBytes(), 0, resetData, 6, 6);

        // --- FIX: Send as PLAINTEXT ---
        System.out.println("Sending Reset PIN Command (PLAINTEXT)...");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_RESET_PIN, 0x00, 0x00, resetData));

        System.out.println("Response SW: " + Integer.toHexString(r.getSW()));
        if (r.getSW() == 0x9000) {
            System.out.println("(Done. Try Verify with New PIN: " + DATA_NEW_PIN + ")");
        } else {
            System.out.println(">>> FAILED");
        }
    }

    private static void unblockCard() throws Exception {
        checkConnection();
        checkPublicKey();

        System.out.println("Unblocking Card (Reset Try Counter)...");
        System.out.print("Enter Admin PIN: ");
        String adminPin = scanner.nextLine();

        if (adminPin.length() != 6) {
            System.out.println("Error: Admin PIN must be 6 characters.");
            return;
        }

        byte[] payload = new byte[6];
        System.arraycopy(adminPin.getBytes(), 0, payload, 0, 6);

        sendSecureCommand(INS_UNBLOCK_PIN, payload);
        System.out.println("(Try Verify with User PIN now)");
    }

    // --- HELPER METHODS ---

    private static void checkConnection() throws Exception {
        if (channel == null)
            throw new Exception("Please Connect (Option 1) first!");
    }

    private static void checkPublicKey() throws Exception {
        if (cardPublicKey == null)
            throw new Exception("Please Get Public Key (Option 2) first!");
    }

    private static void sendSecureCommand(byte ins, byte[] rawData) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey sessionKey = keyGen.generateKey();

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, cardPublicKey);
        byte[] encryptedSessionKey = rsaCipher.doFinal(sessionKey.getEncoded());

        int blockSize = 16;
        int paddedLength = ((rawData.length / blockSize) + 1) * blockSize;
        if (rawData.length % blockSize == 0 && rawData.length > 0) {
            paddedLength = rawData.length;
        } else if (rawData.length == 0) {
            paddedLength = 16;
        }

        byte[] paddedData = new byte[paddedLength];
        System.arraycopy(rawData, 0, paddedData, 0, rawData.length);

        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
        Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
        byte[] encryptedData = aesCipher.doFinal(paddedData);

        byte[] apduData = new byte[encryptedSessionKey.length + encryptedData.length];
        System.arraycopy(encryptedSessionKey, 0, apduData, 0, encryptedSessionKey.length);
        System.arraycopy(encryptedData, 0, apduData, encryptedSessionKey.length, encryptedData.length);

        System.out.println("Sending Secure CMD (INS: " + String.format("0x%02X", ins) + ")...");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, ins, 0x00, 0x00, apduData));

        System.out.println("Response SW: " + Integer.toHexString(r.getSW()));
        if (r.getSW() == 0x9000) {
            System.out.println(">>> SUCCESS");
        } else {
            System.out.println(">>> FAILED (SW: " + Integer.toHexString(r.getSW()) + ")");
        }
    }

    private static PublicKey fetchCardPublicKey(CardChannel channel) throws Exception {
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_GET_PUBLIC_KEY, 0x00, 0x00, 256));
        if (r.getSW1() == 0x6C) {
            r = channel.transmit(new CommandAPDU(0x00, INS_GET_PUBLIC_KEY, 0x00, 0x00, r.getSW2()));
        }
        if (r.getSW() != 0x9000)
            throw new RuntimeException("Get PubKey failed: " + Integer.toHexString(r.getSW()));

        byte[] modulusBytes = r.getData();
        BigInteger modulus = new BigInteger(1, modulusBytes);
        BigInteger exponent = BigInteger.valueOf(65537);
        RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(rsaSpec);
    }

    public static byte[] createFixedLengthData(String text, int length) {
        byte[] result = new byte[length];
        byte[] source = text.getBytes();
        int copyLen = Math.min(source.length, length);
        System.arraycopy(source, 0, result, 0, copyLen);
        return result;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static void getPinTries() {
        try {
            if (channel == null) {
                System.out.println("Card not connected!");
                return;
            }

            System.out.println("Getting PIN Tries...");
            ResponseAPDU response = channel.transmit(new CommandAPDU(0x00, INS_GET_PIN_TRIES, 0x00, 0x00));

            if (response.getSW() != 0x9000) {
                System.out.println("Failed to get PIN Tries. SW: " + String.format("%04X", response.getSW()));
                return;
            }

            byte[] data = response.getData();
            if (data.length < 1) {
                System.out.println("Error: Empty response data");
                return;
            }

            // Lay byte dau tien
            byte tries = data[0];
            System.out.println("PIN Tries: " + tries);

            if (tries >= 3) {
                System.out.println(">>> CARD IS BLOCKED!");
            } else {
                System.out.println(">>> Remaining attempts: " + (3 - tries));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
