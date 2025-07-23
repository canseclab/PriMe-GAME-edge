import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.io.UnsupportedEncodingException;
import java.io.File;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.ByteBuffer;

public class EdgeController {
    // Edge controller's master secert key(msk)
    public static Element alpha, beta, gamma, s;
    // Edge controller's public parameters(params)
    public static Element g, g1, g2, h;
    public static Element delta_j, e_j, l1, l2, J1, J2, tmp;
    public static Element PK_k, SK_k;
    public static Element psi, big_psi, phi, X1, X2, X3;
    public static Element t, C1, C2, C3;
    public static Element Y1, Y2, Y3, psi_inverse, K_i, SK_i, element_f_key;
    public static Element R_prime, Y_prime, C2_prime;
    public static Element g_SK_k, phi_eq, element_index;
    public static String hashString_phi_32, str_R_ind_add, f_key, plaintext, key, ciphertext;
    public static AES_Object use;
    public static String mode = "CBC", IV;
    public static byte[] byteArray_phi_eq, phi_hash_eq, index;
    public static String hashString_phi_eq, hashString_phi_32_eq, Decrypt_text_phi_CT_phi, CT_phi;
    public static Element invers_SK_k, Y_prime_tmp_2, Y1_Y_prime_inv, Y1_Y_prime_Y3, X3_Y2, g2_X3_y2;
    public static Element result_x2_l2, invers_l1, R_prime_tmp, Y_prime_tmp;
    public static byte[] byteArray_X2_l2, H_X2_l2, R1, R;
    public static Element U, V, W, W_tmp;
    public static MessageDigest digest;
    public static Combine combination;
    // Create field(there is a raw type warning)
    @SuppressWarnings("rawtypes")
    public static Field Zq, G1;

    public static Element tmp_dup, tmp_dup2;

    public static void main(String[] args) throws Exception {
        long Setup_startTime = System.currentTimeMillis();
        // Key management and distribution
        // The bits will affect the size of numbers
        int rBits = 160;
        int qBits = 512;
        TypeACurveGenerator A_pro_gen = new TypeACurveGenerator(rBits, qBits);
        PairingParameters type_A_params = A_pro_gen.generate();
        Pairing pairing = PairingFactory.getPairing(type_A_params);
        /*
         * Zq = pairing.getZr();
         * G1 = pairing.getG1();
         * 
         * // Edge controller choose alpha, beta, gamma, s
         * alpha = Zq.newRandomElement().getImmutable();
         * beta = Zq.newRandomElement().getImmutable();
         * gamma = Zq.newRandomElement().getImmutable();
         * s = Zq.newRandomElement().getImmutable();
         * 
         * // Edge controller choose g, trapdoor function(F) and calculate g, g1, and g2
         * // g
         * g = G1.newRandomElement().getImmutable();
         * // h = g^gamma
         * h = g.powZn(gamma.duplicate());
         * // g1 = g^beta
         * g1 = g.powZn(beta.duplicate()).duplicate();
         * // g2 = e(g,h)^alpha
         * Element pair2 = h.duplicate();
         * g2 = pairing.pairing(g, pair2).powZn(alpha.duplicate());
         */
        Setup(pairing);
        long Setup_endTime = System.currentTimeMillis();
        long Setup_durationMillis = Setup_endTime - Setup_startTime;
        System.out.println("Setup time is: " + Setup_durationMillis + " milliseconds");

        // Trapdoor function using AES
        // Key Generation(IDi, params, msk) ri = F(IDi)5

        Scanner sc = new Scanner(System.in);
        System.out.println("Please enter your ID:");
        plaintext = sc.nextLine(); // plaintext == IDa
        use = new AES_Object();
        int keylength = 256;
        key = use.GetKey(keylength);
        // String mode = "CBC";
        IV = use.GetIV();

        long totalEncTime = 0;
        for (int i = 0; i < 100; i++) {
            long startEncTime = System.nanoTime();
            ciphertext = use.encryptAES(plaintext, key, mode, IV);
            long endEncTime = System.nanoTime();
            totalEncTime += (endEncTime - startEncTime);
        }
        double avgEncTimeMillis = totalEncTime / 1_000_000.0 / 100;

        String Decrypt_text = "";
        long totalDecTime = 0;
        for (int i = 0; i < 1; i++) {
            long startDecTime = System.nanoTime();
            Decrypt_text = use.decryptAES(ciphertext, key, mode, IV);
            long endDecTime = System.nanoTime();
            totalDecTime += (endDecTime - startDecTime);
        }
        double avgDecTimeMillis = totalDecTime / 1_000_000.0 / 1;

        System.out.println("----------------Encrypting-----------------\n");
        System.out.println("The Ciphertext is \"" + ciphertext + "\"\n");
        System.out.println("AES Encryption avg. time: " + avgEncTimeMillis + " ms");
        System.out.println("----------------Decrypting-----------------\n");
        System.out.println("The Plaintext is \"" + Decrypt_text + "\"\n");
        System.out.println("AES Decryption avg. time: " + avgDecTimeMillis + " ms");
        System.out.println("-------------------------------------------");

        long KeyGen_startTime = System.currentTimeMillis();
        /*
         * byte[] decodedBytes = Base64.getDecoder().decode(ciphertext);
         * Element r_i = G1.newElementFromBytes(decodedBytes);
         * // user secret key
         * SK_i = g.powZn(r_i.duplicate()).duplicate();
         * 
         * // ZC_j(Zonal controller)
         * // Control key = (rs, g^delta_j) = (l1,l2)
         * delta_j = Zq.newRandomElement();
         * e_j = Zq.newRandomElement().getImmutable();
         * // l1 = rs
         * l1 = gamma.duplicate().mul(s.duplicate());
         * 
         * // l2 = g^delta_j
         * l2 = g.powZn(delta_j.duplicate()).duplicate();
         * // public key = (g^e_j, g^delta_j.e_j) = (J1, J2)
         * // J1 = g^e_j
         * J1 = g.powZn(e_j.duplicate()).duplicate();
         * // J2 = g^(delta_j.e_j)
         * tmp = delta_j.mul(e_j);
         * J2 = g.powZn(tmp.duplicate()).duplicate();
         * 
         * // ED_k(Edge device)
         * SK_k = Zq.newRandomElement().getImmutable();
         * tmp = e_j.duplicate().mul(SK_k.duplicate());
         * PK_k = g.powZn(tmp.duplicate()).duplicate();
         */
        KeyGen();
        long KeyGen_endTime = System.currentTimeMillis();
        long KeyGen_durationMillis = KeyGen_endTime - KeyGen_startTime;
        System.out.println("KeyGen time is: " + KeyGen_durationMillis + " milliseconds");
        // Share set
        // Authoriziaztion token {IDa, IDb, Sb, Sb'}, Sb belongs to {1, ..., n},
        // Sb' = {Xi : Xi = H(IDb || H(SKa * g^i))} for all i belongs to Sb
        long Extract_startTime = System.currentTimeMillis();

        int Sb = 1;
        for (int i = 0; i < Sb; i++) {
            byte[] hash = { 0 };
            long totalNanoiTime = 0;

            Element i_Element = G1.newElement(i);
            Element g_i = g.powZn(i_Element.duplicate()).duplicate();
            Element SK_Gi = SK_i.mul(g_i);
            byte[] elementBytes = SK_Gi.toBytes();
            digest = MessageDigest.getInstance("SHA-256");

            for (int j = 0; j < 100; j++) {
                long startTime = System.nanoTime();
                hash = digest.digest(elementBytes);
                long endTime = System.nanoTime();
                totalNanoiTime += (endTime - startTime);
            }
            double avgTimeMillis = (double) totalNanoiTime / 1000000;
            System.out.println("SHA-256 avg. time: " + avgTimeMillis / 100 + " ms");

            byte[] IDb = new byte[] { 1, 2, 3 };
            combination = new Combine();
            byte[] combinedBytes = combination.concatenate(IDb, hash);
            byte[] Xi_hash = digest.digest(combinedBytes);

            // Extract(msk, IDa, IDb, Sb, Sb')
            // rb = F(IDb)
            String string_IDb = new String(IDb);
            String ciphertext_rb = use.encryptAES(string_IDb, key, mode, IV);
            // For all i belongs to Sb, checks whether Xi ?= H(IDb || H(g^F(IDa) + i))
            String ciphertext_IDa = use.encryptAES(plaintext, key, mode, IV);
            byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext_IDa);
            Element ciphertextElement = pairing.getG1().newElementFromBytes(ciphertextBytes);
            Element result = ciphertextElement.add(i_Element);
            Element e_result = g.powZn(result.duplicate()).duplicate();
            byte[] elementBytes_1 = e_result.toBytes();
            byte[] hash_1 = digest.digest(elementBytes_1);
            byte[] combinedBytes_1 = combination.concatenate(IDb, hash_1);
            byte[] Xi_hash_1 = digest.digest(combinedBytes_1);
            boolean isEqual1And2 = Arrays.equals(Xi_hash, Xi_hash_1);
            System.out.println("Xi =? H(ID_b || H(g^F(ID_a) + i)) : " + isEqual1And2);
            byte[] byteArray = ByteBuffer.allocate(4).putInt(i).array();
            byte[] byteArray_1 = plaintext.getBytes();

            // System.out.println("Bytes:" + byteArray_1.length);

            byte[] combinedBytes_i_IDa = combination.concatenate(byteArray, byteArray_1);
            byte[] li = digest.digest(combinedBytes_i_IDa);
            byte[] bytes_rb = Base64.getDecoder().decode(ciphertext_rb);
            Element element_rb = pairing.getZr().newElementFromBytes(bytes_rb);
            Element element_li = pairing.getZr().newElementFromBytes(li);
            Element result_a = element_rb.add(alpha);
            Element result_b = element_li.add(beta);
            Element inverse_s = s.invert();
            Element result_c = result_b.add(inverse_s);
            Element result_final = result_a.div(result_c);
            // Computes Ki = h^((alpha + rb) / (beta + li + s^-1)) where li = H(i ||IDa)
            // Aggregate key AKSb = {Ki} for all i belongs to Sb
            K_i = h.powZn(result_final);
        }

        long Extract_endTime = System.currentTimeMillis();
        long Extract_durationMillis = Extract_endTime - Extract_startTime;
        System.out.println("Extract time is: " + Extract_durationMillis + " milliseconds");

        // File upload
        long file_upload_startTime = System.currentTimeMillis();
        String filePath = "C:\\Users\\ethan\\Desktop\\test.txt";
        File file = new File(filePath);
        try {
            // try to open file
            if (file.createNewFile()) {
                System.out.println("file is created" + file.getAbsolutePath());
            } else {
                System.out.println("file already exsit");
            }
        } catch (IOException e) {
            // error
            System.out.println("file error：" + e.getMessage());
        }

        f_key = use.GetKey(keylength);
        // CT(ciphertext) = SE(f_key, file) for a random key f_key
        String fileContent = readFileToString(filePath);
        String CT = use.encryptAES(fileContent, f_key, mode, IV);
        System.out.println("CT : " + CT);

        // int CT_bitsize = CT.length() * 8;
        // System.out.println(CT_bitsize);

        file_upload(pairing);
        long file_upload_endTime = System.currentTimeMillis();
        long file_upload_durationMillis = file_upload_endTime - file_upload_startTime;
        System.out.println("File upload time is: " + file_upload_durationMillis + " milliseconds");
        // C = <C1, C2, C3>
        // Uploads Omega = (CT, C) to the cloud

        // File download
        long U_algo_startTime = System.currentTimeMillis();
        /*
         * psi = Zq.newRandomElement().getImmutable();
         * // Compute_psi= e(J2,g^psi)
         * tmp = g.powZn(psi.duplicate()).duplicate();
         * big_psi = pairing.pairing(J2, tmp);
         * // R = H(ID_b) XOR H(psi)
         * byte[] ID_b = new byte[] { 1, 2, 3 };
         * byte[] IDb_hash = digest.digest(ID_b);
         * byte[] big_psi_arr = big_psi.toBytes();
         * byte[] big_psi_hash = digest.digest(big_psi_arr);
         * R = new byte[IDb_hash.length];
         * for (int i = 0; i < R.length; i++) {
         * R[i] = (byte) (IDb_hash[i] ^ big_psi_hash[i]);
         * }
         * // phi = e(Pk_k, g^psi)
         * phi = pairing.pairing(PK_k, tmp);
         * // CT_phi = SE(phi, R || index || f_addr)
         * byte[] combinedBytes_1 = combination.concatenate(R, index);
         * byte[] file_addr = filePath.getBytes();
         * byte[] combinedBytes_2 = combination.concatenate(combinedBytes_1, file_addr);
         * byte[] byteArray_phi = phi.toBytes();
         * byte[] phi_hash = digest.digest(byteArray_phi);
         * String hashString_phi = bytesToHex(phi_hash);
         * String hashString_phi_32 = hashString_phi.substring(0, 32);
         * String str_R_ind_add = new String(combinedBytes_2);
         */
        req_part1(pairing, filePath);
        CT_phi = use.encryptAES(str_R_ind_add, hashString_phi_32, mode, IV);
        // acc_token(X1, X2,X3) = (CT_phi, J1^psi, h^psi)
        // X1 is CT_phi
        // X1 transfer to Elememt?

        req_part2();
        long U_algo_endTime = System.currentTimeMillis();
        long U_algo_durationMillis = U_algo_endTime - U_algo_startTime;
        System.out.println("The U algorithm run time is: " + U_algo_durationMillis + " milliseconds");
        // Submit req = <acc_token, temp_key) to the ED_k

        // Extr(params, acc_token, SK_k) to retrieve f_type and f_addr
        // Calculates phi = e(X2, g^SK_k)
        long Extr_startTime = System.currentTimeMillis();

        EXtr(pairing);
        String Decrypt_text_phi_CT_phi = use.decryptAES(CT_phi, hashString_phi_32_eq, mode, IV);
        long Extr_endTime = System.currentTimeMillis();
        long Extr_durationMillis = Extr_endTime - Extr_startTime;
        System.out.println("File download Extr time is: " + Extr_durationMillis + " milliseconds");

        // Anonymously receives remote file

        // ED_k sends R, X2, X3 and C3 to ZC_j
        // ZC_j executes G_M and transmit acc_token to ED_k
        // Computes R1 = R XOR e(X2, l2)
        long GM_algo_startTime = System.currentTimeMillis();

        GM(pairing);
        long GM_algo_endTime = System.currentTimeMillis();
        long GM_algo_durationMillis = GM_algo_endTime - GM_algo_startTime;
        System.out.println("The GM algorithm run time is: " + GM_algo_durationMillis + " milliseconds");

        long GR_algo_startTime = System.currentTimeMillis();

        GR(pairing);
        long GR_algo_endTime = System.currentTimeMillis();
        long GR_algo_durationMillis = GR_algo_endTime - GR_algo_startTime;
        System.out.println("The GR algorithm run time is: " + GR_algo_durationMillis + " milliseconds");

        long Decrypt_startTime = System.currentTimeMillis();
        /*
         * U = pairing.pairing(SK_i, C3);
         * V = pairing.pairing(C2_prime, K_i);
         * W_tmp = C1.mul(U);
         * Element inverse_V = V.invert();
         * W = W_tmp.mul(inverse_V);
         * boolean isEqual2 = element_f_key.isEqual(W);
         * if (isEqual2) {
         * System.out.println("W and f_key are equal.");
         * } else {
         * System.out.println("W and f_key are not equal.");
         * }
         */
        Decrypt(pairing, SK_i, element_f_key);
        long Decrypt_endTime = System.currentTimeMillis();
        long Decrypt_durationMillis = Decrypt_endTime - Decrypt_startTime;
        System.out.println("Decrypt time is: " + Decrypt_durationMillis + " milliseconds");

        sc.close();
    }

    public static String readFileToString(String filePath) {
        StringBuilder contentBuilder = new StringBuilder();

        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(filePath)))) {
            String line;
            while ((line = br.readLine()) != null) {
                contentBuilder.append(line).append("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return contentBuilder.toString();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void Decrypt(Pairing pairing, Element SK_i, Element element_f_key) {
        U = pairing.pairing(SK_i, C3);
        V = pairing.pairing(C2_prime, K_i);
        W_tmp = C1.mul(U);
        Element inverse_V = V.invert();
        W = W_tmp.mul(inverse_V);
        boolean isEqual2 = element_f_key.isEqual(W);
        if (isEqual2) {
            System.out.println("W and f_key are equal.");
        } else {
            System.out.println("W and f_key are not equal.");
        }
    }

    public static void GR(Pairing pairing) {
        invers_SK_k = SK_k.invert();
        Y_prime_tmp_2 = Y_prime.powZn(invers_SK_k.duplicate()).duplicate();
        Y1_Y_prime_inv = Y1.duplicate().mul(Y_prime_tmp_2.duplicate());
        Y1_Y_prime_Y3 = pairing.pairing(Y1_Y_prime_inv, Y3);
        X3_Y2 = pairing.pairing(X3, Y2);
        g2_X3_y2 = g2.duplicate().mul(X3_Y2.duplicate());
        boolean isEqual = Y1_Y_prime_Y3.isEqual(g2_X3_y2);
        if (isEqual) {
            System.out.println("The two elements check by GR are not equal.");
            System.exit(0);
        } else {
            System.out.println("The two elements check by GR are equal.");
            C2_prime = R_prime.powZn(invers_SK_k.duplicate()).duplicate();
            // return C' = < C1, C2', C3>
        }
    }

    public static void GM(Pairing pairing) {
        result_x2_l2 = pairing.pairing(X2, l2);
        byteArray_X2_l2 = result_x2_l2.toBytes();
        H_X2_l2 = digest.digest(byteArray_X2_l2);
        R1 = new byte[H_X2_l2.length];
        for (int i = 0; i < H_X2_l2.length; i++) {
            R1[i] = (byte) (R[i] ^ H_X2_l2[i]);
        }
        // Check that R1 does not belong to RL(revoction list), ABORT if FALSE ***
        // acc_key = <R', Y'>
        invers_l1 = l1.invert();
        R_prime_tmp = C3.powZn(invers_l1.duplicate()).duplicate();
        R_prime = R_prime_tmp.powZn(SK_k.duplicate()).duplicate();
        Y_prime_tmp = X3.powZn(invers_l1.duplicate()).duplicate();
        Y_prime = Y_prime_tmp.powZn(SK_k.duplicate()).duplicate();
    }

    public static void EXtr(Pairing pairing) {
        g_SK_k = g.powZn(SK_k.duplicate()).duplicate();
        phi_eq = pairing.pairing(X2, g_SK_k);
        System.out.println("Is the phi equal? : " + phi_eq.isEqual(phi));

        // Retrieve R, f_type and f_addr by SD(phi, CT_phi), each length???
        byteArray_phi_eq = phi_eq.toBytes();
        phi_hash_eq = digest.digest(byteArray_phi_eq);
        hashString_phi_eq = bytesToHex(phi_hash_eq);
        hashString_phi_32_eq = hashString_phi_eq.substring(0, 32);
    }

    public static void req_part1(Pairing pairing, String filePath) {
        psi = Zq.newRandomElement().getImmutable();
        // Compute_psi= e(J2,g^psi)
        tmp = g.powZn(psi.duplicate()).duplicate();
        big_psi = pairing.pairing(J2, tmp);
        // R = H(ID_b) XOR H(psi)
        byte[] ID_b = new byte[] { 1, 2, 3 };
        byte[] IDb_hash = digest.digest(ID_b);
        byte[] big_psi_arr = big_psi.toBytes();
        byte[] big_psi_hash = digest.digest(big_psi_arr);
        R = new byte[IDb_hash.length];
        for (int i = 0; i < R.length; i++) {
            R[i] = (byte) (IDb_hash[i] ^ big_psi_hash[i]);
        }
        // phi = e(Pk_k, g^psi)
        phi = pairing.pairing(PK_k, tmp);
        // CT_phi = SE(phi, R || index || f_addr)
        byte[] combinedBytes_1 = combination.concatenate(R, index);
        byte[] file_addr = filePath.getBytes();
        byte[] combinedBytes_2 = combination.concatenate(combinedBytes_1, file_addr);
        byte[] byteArray_phi = phi.toBytes();
        byte[] phi_hash = digest.digest(byteArray_phi);
        String hashString_phi = bytesToHex(phi_hash);
        hashString_phi_32 = hashString_phi.substring(0, 32);
        str_R_ind_add = new String(combinedBytes_2);
    }

    public static void req_part2() {
        X2 = J1.powZn(psi.duplicate()).duplicate();
        X3 = h.powZn(psi.duplicate()).duplicate();
        Element bata_index = beta.add(element_index);
        Element psi_beta_index = bata_index.mul(psi);
        Y1 = g.powZn(psi_beta_index.duplicate()).duplicate();
        psi_inverse = psi.invert();
        Y2 = SK_i.powZn(psi_inverse.duplicate()).duplicate();
        Y3 = K_i.powZn(psi_inverse.duplicate()).duplicate();
    }

    public static void file_upload(Pairing pairing) {
        t = Zq.newRandomElement();
        // C1 = f_key * g2^t
        tmp_dup = g2.duplicate();
        tmp = tmp_dup.powZn(t.duplicate()).duplicate();
        element_f_key = pairing.getGT().newElementFromBytes(f_key.getBytes());
        C1 = element_f_key.mul(tmp); //
        // index = H(f_type || IDa)
        byte[] f_type = new byte[] { 3 };
        byte[] byteArray_IDa = plaintext.getBytes();
        combination = new Combine();
        byte[] combinedBytes_index = combination.concatenate(f_type, byteArray_IDa);
        // digest = MessageDigest.getInstance("SHA-256");
        index = digest.digest(combinedBytes_index);
        element_index = pairing.getZr().newElementFromBytes(index);
        // C2 = (g1 * g^index)^t
        Element g_index = g.powZn(element_index.duplicate()).duplicate();
        Element g1_g_index = g1.mul(g_index);
        C2 = g1_g_index.powZn(t);
        // C3 = h^t
        tmp_dup2 = h.duplicate();
        C3 = tmp_dup2.powZn(t.duplicate()).duplicate();
    }

    public static void KeyGen() {
        byte[] decodedBytes = Base64.getDecoder().decode(ciphertext);
        Element r_i = G1.newElementFromBytes(decodedBytes);
        // user secret key
        SK_i = g.powZn(r_i.duplicate()).duplicate();

        // ZC_j(Zonal controller)
        // Control key = (rs, g^delta_j) = (l1,l2)
        delta_j = Zq.newRandomElement();
        e_j = Zq.newRandomElement().getImmutable();
        // l1 = rs
        l1 = gamma.duplicate().mul(s.duplicate());

        // l2 = g^delta_j
        l2 = g.powZn(delta_j.duplicate()).duplicate();
        // public key = (g^e_j, g^delta_j.e_j) = (J1, J2)
        // J1 = g^e_j
        J1 = g.powZn(e_j.duplicate()).duplicate();
        // J2 = g^(delta_j.e_j)
        tmp = delta_j.mul(e_j);
        J2 = g.powZn(tmp.duplicate()).duplicate();

        // ED_k(Edge device)
        SK_k = Zq.newRandomElement().getImmutable();
        tmp = e_j.duplicate().mul(SK_k.duplicate());
        PK_k = g.powZn(tmp.duplicate()).duplicate();
    }

    public static void Setup(Pairing pairing) {
        Zq = pairing.getZr();
        G1 = pairing.getG1();

        // Edge controller choose alpha, beta, gamma, s
        alpha = Zq.newRandomElement().getImmutable();
        beta = Zq.newRandomElement().getImmutable();
        gamma = Zq.newRandomElement().getImmutable();
        s = Zq.newRandomElement().getImmutable();

        // int s_bitSize = s.getLengthInBytes() * 8;
        // System.out.println("s 的 bit 數: " + s_bitSize);

        // Edge controller choose g, trapdoor function(F) and calculate g, g1, and g2
        // g
        g = G1.newRandomElement().getImmutable();
        long totalNanoTime = 0;
        // h = g^gamma
        for (int i = 0; i < 100; i++) {
            long startTime = System.nanoTime(); // 開始計時
            h = g.powZn(gamma.duplicate());
            long endTime = System.nanoTime(); // 結束計時
            totalNanoTime += (endTime - startTime);
        }
        double avgTimeMillis = totalNanoTime / 1_000_000.0; // 轉換為毫秒
        System.out.println("Exponentiation in G1 avg. Time: " + avgTimeMillis / 100 + " ms");
        // g1 = g^beta
        g1 = g.powZn(beta.duplicate()).duplicate();
        // g2 = e(g,h)^alpha
        Element pair2 = h.duplicate();

        totalNanoTime = 0;
        for (int i = 0; i < 100; i++) {
            long startTime = System.nanoTime();
            g2 = pairing.pairing(g, pair2).powZn(alpha.duplicate());
            long endTime = System.nanoTime();
            totalNanoTime += (endTime - startTime);
        }
        avgTimeMillis = totalNanoTime / 1_000_000.0; // 轉換為毫秒
        System.out.println("Bilinear pairing avg. Time: " + avgTimeMillis / 100 + " ms");
    }
}

class AES_Object {
    public String GetKey(int keylength) // 亂數取得Key
    {
        Random ran = new Random();
        int length = keylength / 8;
        String key = "";
        for (int i = 0; i < length; i++) {
            int value = ran.nextInt(62);
            if (value >= 0 && value <= 9)
                key += (char) (value + (int) '0');
            else if (value >= 10 && value <= 35)
                key += (char) (value - 10 + (int) 'a');
            else
                key += (char) (value - 36 + (int) 'A');
        }
        return key;
    }

    public String GetIV() // 取得IV
    {
        Calendar now = Calendar.getInstance(); // 建立Calendar物件 已取得時間
        String IV = "";
        IV += now.get(Calendar.YEAR);
        IV += now.get(Calendar.MONTH);
        IV += now.get(Calendar.DAY_OF_MONTH);
        IV += now.get(Calendar.HOUR);
        IV += now.get(Calendar.MINUTE);
        IV += now.get(Calendar.SECOND);
        IV += now.get(Calendar.MILLISECOND); // 取得年份、月份、日期、小時
        IV += "0000"; // 分鐘、秒、毫秒，為避免不滿16位數
        IV = IV.substring(0, 16); // 補零再取0-16位數作為IV
        return IV;
    }

    public String default_IV = "0123456789123456";
    public String default_mode = "CBC";

    public String encryptAES(String content, String key, String mode, String IV) // 加密Function
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, UnsupportedEncodingException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        byte[] byteContent = content.getBytes("UTF-8");

        byte[] enCodeFormat = key.getBytes();
        // System.out.println(enCodeFormat.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, "AES");

        byte[] initParam = IV.getBytes();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initParam);

        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding"); // 決定mode
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(byteContent);

        Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(encryptedBytes);
    }

    public String decryptAES(String content, String key, String mode, String IV) // 解密Function
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

        Decoder decoder = Base64.getDecoder();
        byte[] encryptedBytes = decoder.decode(content);

        byte[] enCodeFormat = key.getBytes();
        SecretKeySpec secretKey = new SecretKeySpec(enCodeFormat, "AES");

        byte[] initParam = IV.getBytes();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initParam);

        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding"); // 決定mode
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] result = cipher.doFinal(encryptedBytes);

        return new String(result, "UTF-8");
    }

    public byte[] File_encrypt(byte[] byteContent, byte[] enCodeFormat) // Encrypt file
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, UnsupportedEncodingException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, "AES");

        byte[] initParam = default_IV.getBytes();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initParam);

        Cipher cipher = Cipher.getInstance("AES/" + default_mode + "/PKCS5Padding"); // 決定mode
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(byteContent);

        return encryptedBytes;
    }

    public byte[] File_decrypt(byte[] encryptedBytes, byte[] enCodeFormat) // decrypt file
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

        SecretKeySpec secretKey = new SecretKeySpec(enCodeFormat, "AES");

        byte[] initParam = default_IV.getBytes();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initParam);

        Cipher cipher = Cipher.getInstance("AES/" + default_mode + "/PKCS5Padding"); // 決定mode
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] result = cipher.doFinal(encryptedBytes);

        return result;
    }

    public class BinaryConverter {
        public static String convertToBinary(String input) {
            StringBuilder binary = new StringBuilder();
            for (char c : input.toCharArray()) {
                binary.append(Integer.toBinaryString((int) c));
            }
            return binary.toString();
        }
    }
}

class Combine {
    public byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}