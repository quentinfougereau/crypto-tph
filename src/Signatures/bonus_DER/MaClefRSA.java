package Signatures.bonus_DER;// -*- coding: utf-8 -*-

import java.io.*;
import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;

import java.math.BigInteger;

import java.security.Signature;


public class MaClefRSA {
    public static void main(String[] args) throws Exception {

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

        System.out.println("Module n = 0x" + n.toString(16) +
                           " (" + n.bitLength() + " bits)");
        System.out.println("Exposant e = 0x" + e.toString(16) +
                           " (" + e.bitLength() + " bits)");
        System.out.println("Exposant d = 0x" + d.toString(16) +
                           " (" + n.bitLength() + " bits)");
                
        System.out.println("-----------------------");

        /******************************/
        /* Fabrique de la clef privée */
        /******************************/

        KeyFactory usine = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec specClefPrivée = new RSAPrivateKeySpec(n,d);
        RSAPrivateKey clefPrivée = (RSAPrivateKey) usine.generatePrivate(specClefPrivée);

        /************************************/
        /* Enregistrement de la clef privée */
        /************************************/

        FileOutputStream fos = new FileOutputStream("privatekey_1.bin");
        fos.write(clefPrivée.getEncoded());
        fos.close();
        
        /*****************************************/
        /* Fabrique d'une seconde paire de clefs */
        /*****************************************/
        SecureRandom alea = new SecureRandom();
        KeyPairGenerator forge = KeyPairGenerator.getInstance("RSA");
        forge.initialize(1024, alea);
        KeyPair paireDeClefs = forge.generateKeyPair();
        Key clefPublique = paireDeClefs.getPublic();
        Key clefPrivée2 = paireDeClefs.getPrivate();

        /************************************/
        /* Enregistrement de la clef privée */
        /************************************/

        fos = new FileOutputStream("privatekey_2.bin");
        fos.write(clefPrivée2.getEncoded());
        fos.close();

    }
    
    public static String toHex(byte[] donnees) {
        StringBuffer buf = new StringBuffer();
        buf.append("("+ donnees.length + " octets) ");
        for (int i = 0; i != donnees.length; i++) {
            buf.append(" 0x");
            buf.append(String.format("%02X", donnees[i]));
        }
        return buf.toString();
    }    
}

/* privatekey_1.bin, une fois décodée, ressemblera à ceci:
  0 310: SEQUENCE {
  4   1:   INTEGER 0
  7  13:   SEQUENCE {
  9   9:     OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
 20   0:     NULL
       :     }
 22 288:   OCTET STRING, encapsulates {
 26 284:     SEQUENCE {
 30   1:       INTEGER 0
 33 129:       INTEGER
       :         00 AF 79 58 CB 96 D7 AF 4C 2E 64 48 08 93 62 31
       :         CC 56 E0 11 F3 40 C7 30 B5 82 A7 70 4E 55 9E 3D
       :         79 7C 2B 69 7C 4E EC 07 CA 5A 90 39 83 4C 05 66
       :         06 4D 11 12 1F 15 86 82 9E F6 90 0D 00 3E F4 14
       :         48 7E C4 92 AF 7A 12 C3 43 32 E5 20 FA 7A 0D 79
       :         BF 45 66 26 6B CF 77 C2 E0 07 2A 49 1D BA FA 7F
       :         93 17 5A A9 ED BF 3A 74 42 F8 3A 75 D7 8D A5 42
       :         2B AA 49 21 E2 E0 DF 1C 50 D6 AB 2A E4 41 40 AF
       :         2B
165   1:       INTEGER 0
168 128:       INTEGER
       :         35 C8 54 AD F9 EA DB C0 D6 CB 47 C4 D1 1F 9C B1
       :         CB C2 DB DD 99 F2 33 7C BE B2 01 5B 11 24 F2 24
       :         A5 29 4D 28 9B AB FE 6B 48 3C C2 53 FA DE 00 BA
       :         57 AE AE C6 36 3B C7 17 5F ED 20 FE FD 4C A4 56
       :         5E 0F 18 5C A6 84 BB 72 C1 27 46 96 07 9C DE D2
       :         E0 06 D5 77 CA D2 45 8A 50 15 0C 18 A3 2F 34 30
       :         51 E8 02 3B 8C ED D4 95 98 73 AB EF 69 57 4D C9
       :         04 9A 18 82 1E 60 6B 0D 0D 61 18 94 EB 43 4A 59
299   1:       INTEGER 0
302   1:       INTEGER 0
305   1:       INTEGER 0
308   1:       INTEGER 0
311   1:       INTEGER 0
       :       }
       :     }
       :   }
*/

/* En revanche, privatekey_2.bin donnera:
  0 630: SEQUENCE {
  4   1:   INTEGER 0
  7  13:   SEQUENCE {
  9   9:     OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
 20   0:     NULL
       :     }
 22 608:   OCTET STRING, encapsulates {
 26 604:     SEQUENCE {
 30   1:       INTEGER 0
 33 129:       INTEGER
       :         00 8A 86 AF 0D 03 45 34 B6 87 DD 4B 49 0B 37 D0
       :         7D AC 42 D3 D6 4B F6 AB 4F EE 72 C6 34 7A AB F0
       :         F0 98 E4 7F 46 75 4D C0 7B 2C A0 60 57 6B 31 04
       :         A4 80 E2 DD DD 1B 78 19 C0 EF E5 54 3D 60 A9 2C
       :         61 8D 55 F3 45 3B 99 18 46 55 F4 F3 58 6C BC 05
       :         3B 12 52 20 2D 9D 23 EE 67 15 2D 7F 93 5B 1C 01
       :         11 18 C9 E0 3F 8C AD 6F 7F 82 6C 74 5F B9 A9 1D
       :         C3 1C 82 93 76 1C 87 5E 2D 8B E0 EA 2E D6 31 F9
       :         CB
165   3:       INTEGER 65537
170 128:       INTEGER
       :         46 77 80 F0 C3 AB 1E C7 83 91 A4 CC 81 72 61 12
       :         AC E0 49 D6 87 49 F1 97 75 9A D9 0C B5 22 66 2C
       :         5D FA 4E 6C 4F 1B C0 40 68 51 24 F1 13 4C 1A 2A
       :         7C 8D EB 82 A0 88 95 C1 39 C7 94 F4 AC 09 22 D3
       :         B4 D8 44 F7 B4 5F 99 5F BA 38 43 B4 D5 99 3A 09
       :         E8 E2 24 BC F9 C5 64 D1 99 3F 04 03 94 FE 3C 08
       :         73 C7 6A 6B 56 33 6D 31 9F 88 14 4B E0 2B 31 02
       :         C3 07 BB 39 60 B2 C8 54 CF CB CE 1B 3F 37 0F 21
301  65:       INTEGER
       :         00 CB F6 F1 74 B2 59 12 23 B4 41 F2 A8 02 8F 3B
       :         AA 97 2C 89 3D 4C A6 5D 88 20 E6 76 00 97 BE 7B
       :         06 57 56 2A 59 D9 F1 56 16 BA 82 83 96 06 3C 94
       :         0B 7E A0 C2 6A D1 B1 B5 72 C9 3D FE 5A BE 81 F8
       :         D3
368  65:       INTEGER
       :         00 AD DD E9 12 C3 A5 5F 52 CF F5 06 D2 E6 01 3C
       :         3B 93 65 7F 1C 30 19 13 30 A4 61 98 C7 D8 F5 BA
       :         35 15 56 6B ED 96 5C EA 7B A6 6F 9D DB 19 05 F8
       :         1C 1E 41 2B E8 72 2A 32 37 53 AB D4 5A 86 66 60
       :         29
435  64:       INTEGER
       :         6A 95 6D D1 E4 8D 05 1C A1 4A C1 0A 28 E4 3E 72
       :         C3 B2 E3 38 A4 40 5F AA 0E 3F 40 34 C9 17 21 E4
       :         CB 68 DC 92 BD 80 0E D3 AB BD 1E 14 1C C8 35 38
       :         D8 80 1B 78 84 81 CF E6 DE E0 C5 75 18 0E 85 3F
501  64:       INTEGER
       :         0D D1 0C AC 89 0F A3 3B 99 7B 07 47 CB 2F 5D F1
       :         FE 0C 9A C5 4A AD 33 71 32 1E EF 5D 32 48 94 BB
       :         93 2E 82 F5 26 75 CB CC 77 B5 76 FD EA 47 27 28
       :         54 DF 28 F6 17 DC 72 91 22 FD 0C AB 04 F3 2D C1
567  65:       INTEGER
       :         00 AB 93 1D 00 72 21 E0 56 3C B8 C4 5E 3C B3 9D
       :         E2 5A DA F8 37 71 58 FA 6D 2A 11 70 A0 B2 DC FA
       :         4E 9E 70 E5 D9 12 29 B9 C3 56 4F D9 6A 21 00 8E
       :         14 F2 56 82 01 4A 62 B6 6F D9 26 C0 F9 44 08 5A
       :         15
       :       }
       :     }
       :   }
*/

