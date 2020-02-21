package Signatures;// -*- coding: utf-8 -*-

import java.io.*;
import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;

import java.math.BigInteger;

import java.security.Signature;


public class Appendice {
    public static void main(String[] args) throws FileNotFoundException, IOException {

        /***********************************************************************/
        /* La paire de clefs RSA sous la forme de trois BigIntegers: n, e et d */
        /***********************************************************************/

        BigInteger n = new BigInteger(
                                      "00af7958cb96d7af4c2e6448089362"+
                                      "31cc56e011f340c730b582a7704e55"+
                                      "9e3d797c2b697c4eec07ca5a903983"+
                                      "4c0566064d11121f1586829ef6900d"+
                                      "003ef414487ec492af7a12c34332e5"+
                                      "20fa7a0d79bf4566266bcf77c2e007"+
                                      "2a491dbafa7f93175aa9edbf3a7442"+
                                      "f83a75d78da5422baa4921e2e0df1c"+
                                      "50d6ab2ae44140af2b", 16);
        BigInteger e = BigInteger.valueOf(0x10001);
        BigInteger d = new BigInteger(
                                      "35c854adf9eadbc0d6cb47c4d11f9c"+
                                      "b1cbc2dbdd99f2337cbeb2015b1124"+
                                      "f224a5294d289babfe6b483cc253fa"+
                                      "de00ba57aeaec6363bc7175fed20fe"+
                                      "fd4ca4565e0f185ca684bb72c12746"+
                                      "96079cded2e006d577cad2458a5015"+
                                      "0c18a32f343051e8023b8cedd49598"+
                                      "73abef69574dc9049a18821e606b0d"+
                                      "0d611894eb434a59", 16);

        System.out.println("Module n = " + n.toString(10) +
                           " (" + n.bitLength() + " bits)");
        System.out.println("Exposant e = " + e.toString(10) +
                           " (" + e.bitLength() + " bits)");
        System.out.println("Exposant d = " + d.toString(10) +
                           " (" + n.bitLength() + " bits)");
                
        System.out.println("-----------------------");

        /******************************/
        /* Fabrique de la clef privée */
        /******************************/

        try {
            KeyFactory usine = KeyFactory.getInstance("RSA");
            RSAPrivateKeySpec specClefPrivee = new RSAPrivateKeySpec(n,d);
            RSAPrivateKey clefPrivée = (RSAPrivateKey) usine.generatePrivate(specClefPrivee);
            RSAPublicKeySpec specClefPublique = new RSAPublicKeySpec(n, e);
            RSAPublicKey clefPublique = (RSAPublicKey) usine.generatePublic(specClefPublique);
            /***************************************************************/
            /* Calcul et affichage de l'appendice du fichier "Releve.pdf"  */
            /***************************************************************/
            
            FileInputStream fis = new FileInputStream("./src/Signatures/Releve.pdf");
            Signature signeur = Signature.getInstance("MD5withRSA");
            signeur.initSign(clefPrivée);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try {
                byte[] buffer = new byte[1024];
                int nbOctetsLus = fis.read(buffer);               // Lecture du premier morceau
                while ( nbOctetsLus != -1 ) {
                    bos.write(buffer, 0, nbOctetsLus);
                    signeur.update(buffer, 0, nbOctetsLus);
                    nbOctetsLus = fis.read(buffer);               // Lecture du morceau suivant
                }
                fis.close();
                byte[] appendice = signeur.sign();	      
                System.out.println("Appendice de \"Releve.pdf\" avec \"MD5withRSA\": "
                                   + toHex(appendice));

                byte[] resumeMD5 = getResumeMD5(bos.toByteArray());
                System.out.println("Résumé MD5 : " + toHex(resumeMD5));

                byte[] decryptedHash = decrypt("RSA", "ECB", "NoPadding", clefPrivée, resumeMD5);
                System.out.println("Appendice de signature : " + toHex(decryptedHash));

                byte[] encryptedAppendice = encrypt("RSA", "ECB", "NoPadding", clefPublique, appendice);
                System.out.println("Appendice chiffré : " + toHex(encryptedAppendice));

                System.out.println("Appendice à la mano : " + toHex(bourrage(resumeMD5)));

            } catch ( SignatureException ex1 ) {
                System.out.println("Erreur lors du calculde l'appe ice.");
            }                
        } catch (  NoSuchAlgorithmException|InvalidKeySpecException|InvalidKeyException ex ) {
            System.out.println("Impossible de signer avec cette clef.");
        }
    }
    
    public static String toHex(byte[] donnees) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i != donnees.length; i++) {
            buf.append(" 0x");
            buf.append(String.format("%02X", donnees[i]));
        }
        buf.append(" ("+ donnees.length + " octets)");
        return buf.toString();
    }

    /*
    Calcule le résumé MD5 du tableau d'octets donné en paramètre
    */
    public static byte[] getResumeMD5(byte[] value) {
        byte[] resumeMD5 = null;
        try {
            MessageDigest hash = MessageDigest.getInstance("MD5");
            hash.update(value);
            resumeMD5 = hash.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return resumeMD5;
    }

    public static byte[] decrypt(String encryptionAlgorithm, String mode, String padding, Key privateKey, byte[] encryptedData) {
        String transformation = encryptionAlgorithm + "/" + mode + "/" + padding;
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] encrypt(String encryptionAlgorithm, String mode, String padding, Key privateKey, byte[] encryptedData) {
        String transformation = encryptionAlgorithm + "/" + mode + "/" + padding;
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] bourrage(byte[] resumeMD5) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(128);
        byte[] DER = {
                    (byte) 0x30, (byte) 0x20, (byte) 0x30, (byte) 0x0C, (byte) 0x06, (byte) 0x08, (byte) 0x2A, (byte) 0x86,
                    (byte) 0x48, (byte) 0x86, (byte) 0xF7, (byte) 0x0D, (byte) 0x02, (byte) 0x05, (byte) 0x05, (byte) 0x00,
                    (byte) 0x04, (byte) 0x10
        };
        bos.write(0x00);
        bos.write(0x01);
        int nbFF = 128 - (resumeMD5.length + DER.length + 3);
        for (int i = 0; i < nbFF; i++) {
            bos.write(0xFF);
        }
        bos.write(0x00);
        bos.write(DER, 0, DER.length);
        bos.write(resumeMD5, 0, resumeMD5.length);
        try {
            bos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bos.toByteArray();
    }

}

/* 
  $ javac Appendice.java
  $ java  Appendice
  Module n = 1232220410961060140022027618443990735890055...299 (1024 bits)
  Exposant e = 65537 (17 bits)
  Exposant d = 37767385438721355925084255873299726737298...209 (1024 bits)
  -----------------------
  Appendice du fichier "Releve.pdf" selon la JCE: (128 octets)  0x7D 0x9A
  0xE1 0xE4 0x9E 0x9D 0x25 0x60 0x74 0x0F 0x84 0x26 0xB9 0xA8 0xEA 0x67
  0xC3 0xD9 0xBD 0x08 0xE8 0x3E 0x77 0x0A 0x3B 0x5B 0x9D 0x20 0xE8 0xBD
  0xE2 0xA0 0x10 0xB3 0x54 0x79 0x12 0x49 0x7C 0xE5 0x68 0x5C 0xE4 0x94
  0x08 0xA5 0x48 0x80 0x0F 0x9B 0x9B 0xFC 0x57 0x38 0x38 0x48 0xC3 0xB1
  0x30 0x95 0x41 0xE9 0xEE 0xA6 0xFB 0x81 0x27 0x66 0xD2 0x05 0x09 0xF5
  0xFE 0xCD 0xC6 0xB6 0xF3 0xCE 0x7D 0xF3 0xE2 0xFC 0x08 0x01 0x43 0x93
  0xEA 0x5A 0x3D 0x75 0x5D 0x8C 0xEF 0x8F 0x23 0x81 0x26 0x5B 0x56 0xD1
  0x05 0xEA 0x5D 0xF6 0x04 0x7E 0x20 0x91 0xCA 0xAD 0xEF 0x41 0x0D 0xBA
  0x13 0x07 0x9D 0x07 0xF2 0x5A 0x0F 0x1E 0x0F 0x65 0x04 0x2E 0x8E 0x32
  -----------------------
  Le résumé MD5 du fichier "Releve.pdf" est: (16 octets)  0xCC 0xB8 0xA2
  0x1B 0xB6 0xDD 0xCD 0xB1 0x68 0x0A 0x36 0x53 0xD2 0x8D 0xF9 0xF5
  -----------------------
  Déchiffrement du résumé MD5, à la main: (128 octets)  0x41 0x4D 0xBE 0x8D
  0x2F 0xF0 0xFC 0xBA 0xF0 0x9E 0x2E 0x74 0xB0 0x54 0x71 0x8E 0x64 0x82 ...
  ... 0xB2 0x89 0x8A
  -----------------------
  Appendice chiffré avec la clef publique: (128 octets)  0x00 0x01 0xFF
  0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
  0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
  0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
  0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
  0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
  0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
  0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0x00 0x30 0x20 0x30 0x0C 0x06 0x08 0x2A
  0x86 0x48 0x86 0xF7 0x0D 0x02 0x05 0x05 0x00 0x04 0x10 0xCC 0xB8 0xA2
  0x1B 0xB6 0xDD 0xCD 0xB1 0x68 0x0A 0x36 0x53 0xD2 0x8D 0xF9 0xF5 
*/

