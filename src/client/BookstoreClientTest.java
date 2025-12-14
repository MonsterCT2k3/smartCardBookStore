package client;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageOutputStream;
import javax.smartcardio.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.math.BigInteger;
import java.util.*;
import java.io.*;
import java.util.List;
import java.nio.ByteBuffer;

public class BookstoreClientTest {

    // --- APDU INS Constants ---
    private static final byte INS_SETUP_CARD = (byte) 0x10;
    private static final byte INS_INIT_DATA = (byte) 0x15;
    private static final byte INS_UPLOAD_IMAGE = (byte) 0x16;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0x22;
    private static final byte INS_AUTH_GET_CARD_ID = (byte) 0x31;
    private static final byte INS_AUTH_CHALLENGE = (byte) 0x32;
    private static final byte INS_CHANGE_PIN = (byte) 0x25;
    private static final byte INS_UNBLOCK_PIN = (byte) 0x26;
    private static final byte INS_GET_PIN_TRIES = (byte) 0x33;
    private static final byte INS_RESET_PIN = (byte) 0x50;
    private static final byte INS_GET_INFO = (byte) 0x30;
    private static final byte INS_GET_IMAGE = (byte) 0x34;
    private static final byte INS_GET_BALANCE = (byte) 0x53;
    private static final byte INS_DEPOSIT = (byte) 0x54;
    private static final byte INS_PAYMENT = (byte) 0x55;
    private static final byte INS_UPGRADE_SILVER = (byte) 0x60;
    private static final byte INS_UPGRADE_GOLD = (byte) 0x61;
    private static final byte INS_UPGRADE_DIAMOND = (byte) 0x62;
    private static final byte INS_BORROW_BOOK = (byte) 0x56;
    private static final byte INS_RETURN_BOOK = (byte) 0x57;
    private static final byte INS_GET_BORROWED_BOOKS = (byte) 0x58;
    private static final byte INS_ADD_POINT = (byte) 0x59;
    private static final byte INS_USE_POINT = (byte) 0x5A;
    private static final byte INS_UPDATE_INFO = (byte) 0x40;

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

    // Image 20KB
    private static final int DATA_IMAGE_SIZE = 20480;

    // --- State Variables ---
    private static CardChannel channel = null;
    private static PublicKey cardPublicKey = null;
    private static KeyPair appKeyPair = null;
    private static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
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
            System.out.println("5. Init Data (Text + App PubKey)");
            System.out.println("6. Upload Image (Random Data)");
            System.out.println("7. Get User Info (Text Only)");
            System.out.println("8. Get Image (Check Data)");
            System.out.println("9. Reset User PIN");
            System.out.println("10. Change PIN (User)");
            System.out.println("11. Authenticate Card");
            System.out.println("12. Unblock Card (Admin Only)");
            System.out.println("13. Get PIN Tries");
            System.out.println("14. Upload Image from FILE");
            System.out.println("15. Get Image & Save to FILE (Fixed)");
            System.out.println("16. Get Balance");
            System.out.println("17. Deposit Money");
            System.out.println("18. Make Payment");
            System.out.println("19. Upgrade to Silver");
            System.out.println("20. Upgrade to Gold");
            System.out.println("21. Upgrade to Diamond");
            System.out.println("22. Borrow Book");
            System.out.println("23. Return Book");
            System.out.println("24. My Bookshelf");
            System.out.println("25. Add Points");
            System.out.println("26. Use Points");
            System.out.println("27. Update Personal Info");
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
                        uploadImage();
                        break;
                    case "7":
                        getInfo();
                        break;
                    case "8":
                        getImage();
                        break;
                    case "9":
                        resetUserPin();
                        break;
                    case "10":
                        changePin();
                        break;
                    case "11":
                        authenticateUser();
                        break;
                    case "12":
                        unblockCard();
                        break;
                    case "13":
                        getPinTries();
                        break;
                    case "14":
                        uploadImageFromFile();
                        break;
                    case "15":
                        saveImageToFile();
                        break;
                    case "16":
                        getBalance();
                        break;
                    case "17":
                        depositMoney();
                        break;
                    case "18":
                        makePayment();
                        break;
                    case "19":
                        upgradeMember(INS_UPGRADE_SILVER, "Silver");
                        break;
                    case "20":
                        upgradeMember(INS_UPGRADE_GOLD, "Gold");
                        break;
                    case "21":
                        upgradeMember(INS_UPGRADE_DIAMOND, "Diamond");
                        break;
                    case "22":
                        borrowBook();
                        break;
                    case "23":
                        returnBook();
                        break;
                    case "24":
                        getMyBooks();
                        break;
                    case "25":
                        addPoints();
                        break;
                    case "26":
                        usePoints();
                        break;
                    case "27":
                        updateUserInfo();
                        break;
                    case "0":
                        System.out.println("Exiting...");
                        return;
                    default:
                        System.out.println("Invalid option!");
                }
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
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

        Card card = null;
        try {
            card = terminal.connect("T=1");
            System.out.println("Connected with protocol: T=1 (Extended APDU Supported)");
        } catch (CardException e) {
            System.out.println("Warning: T=1 not supported, falling back to *");
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

        byte[] pinData = userPin.getBytes();
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
        byte[] payload = new byte[320];
        int offset = 0;

        System.arraycopy(createFixedLengthData(DATA_CARD_ID, 16), 0, payload, offset, 16);
        offset += 16;
        System.arraycopy(createFixedLengthData(DATA_NAME, 64), 0, payload, offset, 64);
        offset += 64;
        System.arraycopy(createFixedLengthData(DATA_DOB, 16), 0, payload, offset, 16);
        offset += 16;
        System.arraycopy(createFixedLengthData(DATA_PHONE, 16), 0, payload, offset, 16);
        offset += 16;
        System.arraycopy(createFixedLengthData(DATA_ADDRESS, 64), 0, payload, offset, 64);
        offset += 64;
        System.arraycopy(createFixedLengthData(DATA_REG_DATE, 16), 0, payload, offset, 16);
        offset += 16;

        java.security.interfaces.RSAPublicKey rsaPubKey = (java.security.interfaces.RSAPublicKey) appKeyPair
                .getPublic();
        byte[] modulus = rsaPubKey.getModulus().toByteArray();

        byte[] modulusFixed = new byte[128];
        if (modulus.length == 129 && modulus[0] == 0) {
            System.arraycopy(modulus, 1, modulusFixed, 0, 128);
        } else if (modulus.length == 128) {
            System.arraycopy(modulus, 0, modulusFixed, 0, 128);
        } else {
            int padLen = 128 - modulus.length;
            System.arraycopy(modulus, 0, modulusFixed, padLen, modulus.length);
        }
        System.arraycopy(modulusFixed, 0, payload, offset, 128);

        System.out.println("Sending APDU (Size " + payload.length + ")...");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_INIT_DATA, 0x00, 0x00, payload));

        System.out.println("Response SW: " + Integer.toHexString(r.getSW()));
        if (r.getSW() == 0x9000) {
            System.out.println(">>> SUCCESS: Data & App PubKey Initialized.");
        } else {
            System.out.println(">>> FAILED.");
        }
    }

    private static void uploadImage() throws Exception {
        checkConnection();
        System.out.println("Generating Random Image Data (20KB)...");

        byte[] fakeImage = new byte[DATA_IMAGE_SIZE];
        new Random().nextBytes(fakeImage);

        fakeImage[0] = (byte) 0xAA;
        fakeImage[1] = (byte) 0xBB;
        fakeImage[DATA_IMAGE_SIZE - 2] = (byte) 0xCC;
        fakeImage[DATA_IMAGE_SIZE - 1] = (byte) 0xDD;

        System.out.println("Sending Extended APDU (20KB)...");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_UPLOAD_IMAGE, 0x00, 0x00, fakeImage));

        System.out.println("Response SW: " + Integer.toHexString(r.getSW()));
        if (r.getSW() == 0x9000) {
            System.out.println(">>> UPLOAD IMAGE SUCCESS");
        } else {
            System.out.println(">>> UPLOAD FAILED");
        }
    }

    private static void uploadImageFromFile() throws Exception {
        checkConnection();

        String filePath = "D:\\Download\\image\\androidparty.png";
        if (filePath.startsWith("\"") && filePath.endsWith("\"")) {
            filePath = filePath.substring(1, filePath.length() - 1);
        }

        File inputFile = new File(filePath);
        if (!inputFile.exists()) {
            System.out.println("Error: File not found!");
            return;
        }

        // 1. Kiểm tra kích thước ảnh gốc
        long originalSize = inputFile.length();
        System.out.println("Original File Size: " + originalSize + " bytes");

        byte[] imageData;

        // 2. Logic quyết định Nén hay Không
        if (originalSize > DATA_IMAGE_SIZE) {
            System.out.println(">>> Image > 20KB. Compressing...");
            File tempFile = new File("temp_compressed_image.jpg");
            try {
                // Gọi hàm nén ép xuống < 20KB
                compressImage(inputFile, tempFile, DATA_IMAGE_SIZE);

                // Đọc file kết quả
                imageData = new byte[(int) tempFile.length()];
                try (FileInputStream fis = new FileInputStream(tempFile)) {
                    fis.read(imageData);
                }
                System.out.println(">>> Compressed Size: " + imageData.length + " bytes");
            } finally {
                if (tempFile.exists())
                    tempFile.delete();
            }
        } else {
            System.out.println(">>> Image <= 20KB. Skipping compression.");
            imageData = new byte[(int) originalSize];
            try (FileInputStream fis = new FileInputStream(inputFile)) {
                fis.read(imageData);
            }
        }

        if (imageData.length > DATA_IMAGE_SIZE) {
            System.out.println("Error: Failed to compress below 20KB. Aborting.");
            return;
        }

        System.out.println("Sending Image to Card (" + imageData.length + " bytes)...");
        long startTime = System.currentTimeMillis();

        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_UPLOAD_IMAGE, 0x00, 0x00, imageData));

        long duration = System.currentTimeMillis() - startTime;
        System.out.println("Response SW: " + Integer.toHexString(r.getSW()) + " (Time: " + duration + "ms)");

        if (r.getSW() == 0x9000) {
            System.out.println(">>> UPLOAD SUCCESS");
        } else {
            System.out.println(">>> UPLOAD FAILED");
        }
    }

    private static void getInfo() throws Exception {
        checkConnection();
        System.out.println("Getting Info from Card (PLAINTEXT)...");
        // Update request length: 193
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_GET_INFO, 0x00, 0x00, 193));

        if (r.getSW() != 0x9000) {
            System.out.println("Failed. SW: " + Integer.toHexString(r.getSW()));
            return;
        }

        byte[] plainData = r.getData();
        if (plainData.length < 192) {
            System.out.println("Error: Not enough data received.");
            return;
        }

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

        // Doc Member Type (Byte thu 192)
        String memberRank = "Unknown";
        if (plainData.length >= 193) {
            byte type = plainData[192];
            switch (type) {
                case 0:
                    memberRank = "Normal";
                    break;
                case 1:
                    memberRank = "Silver";
                    break;
                case 2:
                    memberRank = "Gold";
                    break;
                case 3:
                    memberRank = "Diamond";
                    break;
                default:
                    memberRank = "Type " + type;
                    break;
            }
        }

        System.out.println("--- User Info ---");
        System.out.println("Card ID : " + cardId);
        System.out.println("Name    : " + name);
        System.out.println("DOB     : " + dob);
        System.out.println("Phone   : " + phone);
        System.out.println("Address : " + address);
        System.out.println("RegDate : " + regDate);
        System.out.println("Rank    : " + memberRank);
    }

    // --- MODIFIED: GET IMAGE (CHUNKED) ---
    private static void getImage() throws Exception {
        checkConnection();
        System.out.println("Downloading Image (20KB) in chunks...");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int offset = 0;
        int chunkSize = 256; // Doc tung chunk nho

        while (offset < DATA_IMAGE_SIZE) {
            // Tinh toan offset de gui P1 P2
            int p1 = (offset >> 8) & 0xFF;
            int p2 = offset & 0xFF;

            // Tinh so luong byte muon doc (Le)
            int remain = DATA_IMAGE_SIZE - offset;
            int toRead = Math.min(remain, chunkSize);

            // Gui lenh
            ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_GET_IMAGE, p1, p2, toRead));

            if (r.getSW() != 0x9000) {
                System.out.println("Failed at offset " + offset + ". SW: " + Integer.toHexString(r.getSW()));
                return;
            }

            byte[] chunk = r.getData();
            baos.write(chunk);
            offset += chunk.length;

            // Hien thi tien do (optional)
            // System.out.print(".");
        }

        byte[] imgData = baos.toByteArray();
        System.out.println("\nReceived Image Len: " + imgData.length);

        if (imgData.length == DATA_IMAGE_SIZE) {
            System.out.println(">>> CHECK DATA MARKERS:");
            System.out.printf("First bytes: %02X %02X\n", imgData[0], imgData[1]);
            System.out.printf("Last bytes : %02X %02X\n", imgData[DATA_IMAGE_SIZE - 2], imgData[DATA_IMAGE_SIZE - 1]);
        }
    }

    // --- MODIFIED: SAVE IMAGE TO FILE (CHUNKED) ---
    private static void saveImageToFile() throws Exception {
        checkConnection();

        String dirPath = "D:\\Download\\image";

        File dir = new File(dirPath);
        if (!dir.exists() || !dir.isDirectory()) {
            System.out.println("Error: Directory not found or invalid.");
            return;
        }

        // Tao ten file tu dong
        String fileName = "download_image_" + System.currentTimeMillis() + ".jpg";
        File outFile = new File(dir, fileName);

        System.out.println("Downloading to: " + outFile.getAbsolutePath());
        long startTime = System.currentTimeMillis();

        // Logic Chunking
        FileOutputStream fos = new FileOutputStream(outFile);
        int offset = 0;
        int chunkSize = 256;

        try {
            while (offset < DATA_IMAGE_SIZE) {
                int p1 = (offset >> 8) & 0xFF;
                int p2 = offset & 0xFF;
                int remain = DATA_IMAGE_SIZE - offset;
                int toRead = Math.min(remain, chunkSize);

                ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_GET_IMAGE, p1, p2, toRead));

                if (r.getSW() != 0x9000) {
                    System.out.println(">>> FAILED at offset " + offset);
                    fos.close();
                    return;
                }

                byte[] chunk = r.getData();
                fos.write(chunk);
                offset += chunk.length;
            }

            fos.close();
            long duration = System.currentTimeMillis() - startTime;
            System.out.println(">>> SUCCESS! Download complete in " + duration + "ms");

        } catch (IOException e) {
            System.out.println("IO Error: " + e.getMessage());
            fos.close();
        }
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

        System.out.println("Sending Change PIN Command (PLAINTEXT)...");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_CHANGE_PIN, 0x00, 0x00, payload));

        System.out.println("Response SW: " + Integer.toHexString(r.getSW()));
        if (r.getSW() == 0x9000) {
            System.out.println(">>> CHANGE PIN SUCCESS");

            // --- ADDED: Refresh Public Key (Key Rotation) ---
            System.out.println("Refreshing Card Public Key...");
            cardPublicKey = null;
            getPublicKey();
        } else {
            System.out.println(">>> CHANGE PIN FAILED");
        }
    }

    private static void authenticateUser() throws Exception {
        checkConnection();
        if (appKeyPair == null) {
            System.out.println("Error: App KeyPair not available.");
            return;
        }
        checkPublicKey();

        System.out.println("\n--- STEP 1: IDENTIFICATION (Get Card ID) ---");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_AUTH_GET_CARD_ID, 0x00, 0x00, 16));
        if (r.getSW() != 0x9000)
            return;

        String cardId = new String(r.getData()).trim();
        System.out.println(">>> Card ID Claimed: " + cardId);

        System.out.println("\n--- STEP 2: AUTHENTICATION (Challenge-Response) ---");
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);
        System.out.println("Challenge Generated: " + bytesToHex(challenge));

        ResponseAPDU r2 = channel.transmit(new CommandAPDU(0x00, INS_AUTH_CHALLENGE, 0x00, 0x00, challenge));
        if (r2.getSW() != 0x9000)
            return;

        byte[] signature = r2.getData();
        System.out.println("Signature Received: " + bytesToHex(signature));

        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(cardPublicKey);
        sig.update(challenge);

        if (sig.verify(signature)) {
            System.out.println(">>> AUTHENTICATION SUCCESSFUL!");
        } else {
            System.out.println(">>> AUTHENTICATION FAILED!");
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

        System.out.println("Sending Reset PIN Command (PLAINTEXT)...");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_RESET_PIN, 0x00, 0x00, resetData));

        System.out.println("Response SW: " + Integer.toHexString(r.getSW()));
        if (r.getSW() == 0x9000) {
            System.out.println("(Done. Try Verify with New PIN: " + DATA_NEW_PIN + ")");

            // --- ADDED: Refresh Public Key (Key Rotation) ---
            System.out.println("Refreshing Card Public Key...");
            cardPublicKey = null;
            getPublicKey();
        } else {
            System.out.println(">>> FAILED");
        }
    }

    private static void unblockCard() throws Exception {
        checkConnection();
        checkPublicKey();
        System.out.println("Unblocking Card...");
        System.out.print("Enter Admin PIN: ");
        String adminPin = scanner.nextLine();

        byte[] payload = new byte[6];
        System.arraycopy(adminPin.getBytes(), 0, payload, 0, 6);

        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_UNBLOCK_PIN, 0x00, 0x00, payload));
        System.out.println("Response SW: " + Integer.toHexString(r.getSW()));
    }

    private static void checkConnection() throws Exception {
        if (channel == null)
            throw new Exception("Please Connect (Option 1) first!");
    }

    private static void checkPublicKey() throws Exception {
        if (cardPublicKey == null)
            throw new Exception("Please Get Public Key (Option 2) first!");
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
            if (channel == null)
                return;
            System.out.println("Getting PIN Tries...");
            ResponseAPDU response = channel.transmit(new CommandAPDU(0x00, INS_GET_PIN_TRIES, 0x00, 0x00));
            if (response.getSW() == 0x9000) {
                byte tries = response.getData()[0];
                System.out.println("PIN Tries: " + tries + " (Left: " + (3 - tries) + ")");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // --- IMAGE COMPRESSION HELPER ---
    public static void compressImage(File inputFile, File outputFile, long targetSize) throws IOException {
        BufferedImage originalImage = ImageIO.read(inputFile);
        if (originalImage == null) {
            throw new IOException("Cannot read image: " + inputFile.getAbsolutePath());
        }

        int width = originalImage.getWidth();
        int height = originalImage.getHeight();

        Iterator<ImageWriter> writers = ImageIO.getImageWritersByFormatName("jpg");
        if (!writers.hasNext())
            throw new IllegalStateException("No writers found for jpg");
        ImageWriter writer = writers.next();

        // 1. Try reducing Quality (Keep Dimensions)
        float quality = 1.0f;
        // Optimization: Create RGB image once for quality reduction phase
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        g.drawImage(originalImage, 0, 0, Color.WHITE, null);
        g.dispose();

        while (quality >= 0.0f) {
            if (outputFile.exists()) {
                outputFile.delete();
            }

            try (ImageOutputStream ios = ImageIO.createImageOutputStream(outputFile)) {
                writer.setOutput(ios);
                ImageWriteParam param = writer.getDefaultWriteParam();
                if (param.canWriteCompressed()) {
                    param.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
                    param.setCompressionQuality(quality);
                }
                writer.write(null, new IIOImage(image, null, null), param);
            }

            if (outputFile.length() <= targetSize) {
                writer.dispose();
                return;
            }

            quality -= 0.05f;
            if (quality < 0.05f && quality > 0.0f)
                quality = 0.0f; // Force hit 0.0f
            else if (quality < 0.0f)
                break;
        }

        // 2. If still too big -> Force Resize (Fallback)
        // Only happens if lowest quality is still > 20KB
        System.out.println(">>> Info: Lowest quality reached but still > 20KB. Starting resize loop...");
        double scale = 0.9;

        while (outputFile.length() > targetSize && scale > 0.05) {
            if (outputFile.exists()) {
                outputFile.delete();
            }

            int newWidth = (int) (width * scale);
            int newHeight = (int) (height * scale);

            // Safety check for tiny images
            if (newWidth < 10 || newHeight < 10)
                break;

            BufferedImage resizedImage = new BufferedImage(newWidth, newHeight, BufferedImage.TYPE_INT_RGB);
            Graphics2D g2 = resizedImage.createGraphics();
            g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
            g2.drawImage(originalImage, 0, 0, newWidth, newHeight, Color.WHITE, null);
            g2.dispose();

            try (ImageOutputStream ios = ImageIO.createImageOutputStream(outputFile)) {
                writer.setOutput(ios);
                ImageWriteParam param = writer.getDefaultWriteParam();
                param.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
                param.setCompressionQuality(0.1f); // Low quality + Resize
                writer.write(null, new IIOImage(resizedImage, null, null), param);
            }
            scale -= 0.1;
        }

        writer.dispose();
    }

    // --- BALANCE METHODS ---
    private static void getBalance() throws Exception {
        checkConnection();
        System.out.println("Getting Balance & Points...");
        // Expect 8 bytes: 4 bytes Balance + 4 bytes Points
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_GET_BALANCE, 0x00, 0x00, 8));
        if (r.getSW() == 0x9000) {
            byte[] data = r.getData();
            if (data.length < 8) {
                System.out.println("Error: Not enough data.");
                return;
            }
            int balance = ByteBuffer.wrap(data, 0, 4).getInt();
            int points = ByteBuffer.wrap(data, 4, 4).getInt();

            System.out.println(">>> Current Balance: " + balance + " VND");
            System.out.println(">>> Reward Points  : " + points);
        } else {
            System.out.println(">>> FAILED. SW: " + Integer.toHexString(r.getSW()));
        }
    }

    private static void depositMoney() throws Exception {
        checkConnection();
        System.out.print("Enter Amount to Deposit: ");
        int amount = Integer.parseInt(scanner.nextLine());

        byte[] data = ByteBuffer.allocate(4).putInt(amount).array();

        System.out.println("Depositing " + amount + "...");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_DEPOSIT, 0x00, 0x00, data));

        System.out.println("Response SW: " + Integer.toHexString(r.getSW()));
        if (r.getSW() == 0x9000) {
            System.out.println(">>> DEPOSIT SUCCESS");
            getBalance();
        } else {
            System.out.println(">>> FAILED");
        }
    }

    private static void upgradeMember(byte ins, String rankName) throws Exception {
        checkConnection();
        System.out.println("Upgrading Membership to " + rankName + "...");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, ins, 0x00, 0x00));

        if (r.getSW() == 0x9000) {
            System.out.println(">>> UPGRADE SUCCESS: You are now a " + rankName + " Member!");
            getInfo();
        } else {
            System.out.println(">>> FAILED. SW: " + Integer.toHexString(r.getSW()));
        }
    }

    // --- BOOK BORROWING ---

    private static void borrowBook() throws Exception {
        checkConnection();
        // Database sach gia lap
        System.out.println("\n--- Available Books ---");
        System.out.println("101. Java Programming (ID: 101)");
        System.out.println("102. Smart Card Security (ID: 102)");
        System.out.println("103. Algorithms (ID: 103)");
        System.out.println("104. Database Systems (ID: 104)");
        System.out.println("105. Network Security (ID: 105)");

        System.out.print("Enter Book ID to Borrow: ");
        String bookIdStr = scanner.nextLine();

        byte[] bookId = new byte[6]; // ID 6 bytes
        byte[] inputId = bookIdStr.getBytes();
        if (inputId.length > 6) {
            System.out.println("ID too long!");
            return;
        }
        Arrays.fill(bookId, (byte) 0);
        System.arraycopy(inputId, 0, bookId, 0, inputId.length);

        // Auto-generate Today's Date
        java.time.LocalDate now = java.time.LocalDate.now();
        java.time.format.DateTimeFormatter formatter = java.time.format.DateTimeFormatter.ofPattern("ddMMyyyy");
        String date = now.format(formatter);
        System.out.println("Borrow Date (Auto): " + date);

        System.out.print("Enter Duration (days): ");
        try {
            int duration = Integer.parseInt(scanner.nextLine());
            if (duration > 255)
                duration = 255;

            System.out.print("Enter Book Type (1=promotion, 0 = normal): ");
            int type = Integer.parseInt(scanner.nextLine());
            if (type > 255)
                type = 255;

            // Build Payload: 6 ID + 8 Date + 1 Duration + 1 Type = 16 bytes
            byte[] payload = new byte[16];
            System.arraycopy(bookId, 0, payload, 0, 6);
            System.arraycopy(date.getBytes(), 0, payload, 6, 8);
            payload[14] = (byte) duration;
            payload[15] = (byte) type;

            System.out.println("Sending Borrow Request...");
            ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_BORROW_BOOK, 0x00, 0x00, payload));

            if (r.getSW() == 0x9000) {
                System.out.println(">>> BORROW SUCCESS!");
            } else if (r.getSW() == 0x6300) {
                System.out.println(">>> FAILED: Book already borrowed or Invalid.");
            } else if (r.getSW() == 0x6A84) { // SW_FILE_FULL
                System.out.println(">>> FAILED: Max books reached (15).");
            } else {
                System.out.println(">>> FAILED. SW: " + Integer.toHexString(r.getSW()));
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid duration!");
        }
    }

    private static void returnBook() throws Exception {
        checkConnection();
        System.out.print("Enter Book ID to Return: ");
        String bookIdStr = scanner.nextLine();

        byte[] bookId = new byte[6]; // ID 6 bytes
        byte[] inputId = bookIdStr.getBytes();
        // Fill 0 padding for safety match
        Arrays.fill(bookId, (byte) 0);
        if (inputId.length <= 6) {
            System.arraycopy(inputId, 0, bookId, 0, inputId.length);
        }

        System.out.println("Returning Book...");
        // Send 6 bytes ID (or full 16 bytes padded is also fine, Applet handles both
        // but prefers 6 minimum)
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_RETURN_BOOK, 0x00, 0x00, bookId));

        if (r.getSW() == 0x9000) {
            System.out.println(">>> RETURN SUCCESS!");
        } else {
            System.out.println(">>> FAILED (Book not found?). SW: " + Integer.toHexString(r.getSW()));
        }
    }

    private static void getMyBooks() throws Exception {
        checkConnection();
        System.out.println("Fetching My Bookshelf...");

        // 15 slots * 16 bytes = 240 bytes
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_GET_BORROWED_BOOKS, 0x00, 0x00, 240));

        if (r.getSW() != 0x9000) {
            System.out.println("Failed. SW: " + Integer.toHexString(r.getSW()));
            return;
        }

        byte[] data = r.getData();
        int count = 0;
        System.out.println("\n--- MY BORROWED BOOKS ---");
        System.out.println(String.format("%-10s | %-12s | %-8s | %-5s", "ID", "BorrowDate", "Duration", "Type"));
        System.out.println("---------------------------------------------------------");

        for (int i = 0; i < 15; i++) {
            int offset = i * 16;
            // Check byte dau tien cua ID
            if (data[offset] != 0) {
                // Parse ID (6 bytes)
                String id = new String(data, offset, 6).trim();
                // Parse Date (8 bytes) at offset + 6
                String date = new String(data, offset + 6, 8);
                // Parse Duration at offset + 14
                int duration = data[offset + 14] & 0xFF;
                // Parse Type at offset + 15
                int type = data[offset + 15] & 0xFF;

                System.out.println(String.format("%-10s | %-12s | %-8d | %-5d", id, date, duration, type));
                count++;
            }
        }

        if (count == 0) {
            System.out.println("(Empty)");
        }
    }

    private static void addPoints() throws Exception {
        checkConnection();
        System.out.print("Enter Points to Add: ");
        int points = Integer.parseInt(scanner.nextLine());

        byte[] data = ByteBuffer.allocate(4).putInt(points).array();

        System.out.println("Adding " + points + " points...");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_ADD_POINT, 0x00, 0x00, data));

        System.out.println("Response SW: " + Integer.toHexString(r.getSW()));
        if (r.getSW() == 0x9000) {
            System.out.println(">>> ADD POINTS SUCCESS");
            getBalance();
        } else {
            System.out.println(">>> FAILED");
        }
    }

    private static void usePoints() throws Exception {
        checkConnection();
        System.out.print("Enter Points to Redeem: ");
        int points = Integer.parseInt(scanner.nextLine());

        byte[] data = ByteBuffer.allocate(4).putInt(points).array();

        System.out.println("Using " + points + " points...");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_USE_POINT, 0x00, 0x00, data));

        if (r.getSW() == 0x9000) {
            System.out.println(">>> REDEEM SUCCESS!");
            getBalance();
        } else if (r.getSW() == 0x6300) {
            System.out.println(">>> FAILED: Not enough points!");
        } else {
            System.out.println(">>> FAILED. SW: " + Integer.toHexString(r.getSW()));
        }
    }

    private static void makePayment() throws Exception {
        checkConnection();
        System.out.print("Enter Amount to Pay: ");
        int amount = Integer.parseInt(scanner.nextLine());

        byte[] data = ByteBuffer.allocate(4).putInt(amount).array();

        System.out.println("Paying " + amount + "...");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_PAYMENT, 0x00, 0x00, data));

        if (r.getSW() == 0x9000) {
            System.out.println(">>> PAYMENT SUCCESS");
            getBalance();
        } else if (r.getSW() == 0x6300) {
            System.out.println(">>> FAILED: Insufficient Balance!");
        } else {
            System.out.println(">>> FAILED. SW: " + Integer.toHexString(r.getSW()));
        }
    }

    private static void updateUserInfo() throws Exception {
        checkConnection();
        System.out.println("Updating Personal Info...");

        System.out.print("Enter Name: ");
        String name = scanner.nextLine();
        System.out.print("Enter DOB (ddMMyyyy): ");
        String dob = scanner.nextLine();
        System.out.print("Enter Phone: ");
        String phone = scanner.nextLine();
        System.out.print("Enter Address: ");
        String address = scanner.nextLine();

        // Build Payload: Name(64) + DOB(16) + Phone(16) + Address(64) = 160 bytes
        byte[] payload = new byte[160];
        int offset = 0;

        System.arraycopy(createFixedLengthData(name, 64), 0, payload, offset, 64);
        offset += 64;
        System.arraycopy(createFixedLengthData(dob, 16), 0, payload, offset, 16);
        offset += 16;
        System.arraycopy(createFixedLengthData(phone, 16), 0, payload, offset, 16);
        offset += 16;
        System.arraycopy(createFixedLengthData(address, 64), 0, payload, offset, 64);

        System.out.println("Sending Update Request (160 bytes)...");
        ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, INS_UPDATE_INFO, 0x00, 0x00, payload));

        if (r.getSW() == 0x9000) {
            System.out.println(">>> UPDATE SUCCESS!");
            getInfo(); // Hien thi lai thong tin sau khi update
        } else {
            System.out.println(">>> FAILED. SW: " + Integer.toHexString(r.getSW()));
        }
    }
}
