package DSA;

import java.io.*;
import java.math.*;
import java.security.*;
import java.security.interfaces.*;

import java.security.spec.*;

class SignatureDSA {

    public static void main(String[] args) throws FileNotFoundException, IOException {
        BigInteger p = new BigInteger("111958263587531251073063992929072615563329246"
                                      + "4249928569863698970919869140603990535804575"
                                      + "8561598618825818684040312145167601150193917"
                                      + "2149448024805299773162859346190124776181616"
                                      + "7366634417932494461727054368709982905338669"
                                      + "5099162745460119184161044903926008505775126"
                                      + "7876837947543468839729453779173929240178949"
                                      + "480737", 10);
        BigInteger q = new BigInteger("126813832202860610388657190695702552295268871"
                                      + "2021", 10);
        BigInteger g = new BigInteger("506023554538257534013810009605918961950898551"
                                      + "6536594430070074550280880967301189606557588"
                                      + "6184794480663901932287973804196793018312465"
                                      + "0136953145980216037460567777567931663153601"
                                      + "3335814956793251831260409956178972866185857"
                                      + "0489003871790607093257743119941862924284895"
                                      + "7833853664686367366692090270188890568473393"
                                      + "39026", 10);
        BigInteger x = new BigInteger("668047990587860039765754389502437352831940887"
                                      + "198", 10);
        BigInteger y = new BigInteger("584124690585743294266491053661670957547878739"
                                      + "8612048496409941378308181881146016436555057"
                                      + "3308951084899153504465438036439614834288473"
                                      + "2829006221995823268660497096760365382424044"
                                      + "2060049204294661864115524032463876863734330"
                                      + "3359632374609307801694560023147454644348573"
                                      + "5317970660047726519053333902204034824620990"
                                      + "38688", 10);

        try {
            KeyFactory usine = KeyFactory.getInstance("DSA");
            DSAPublicKeySpec specClefPublique = new DSAPublicKeySpec(y,p,q,g);
            DSAPublicKey clefPublique = (DSAPublicKey) usine.generatePublic(specClefPublique);
            DSAPrivateKeySpec specClefPrivée = new DSAPrivateKeySpec(x,p,q,g);
            DSAPrivateKey clefPrivée = (DSAPrivateKey) usine.generatePrivate(specClefPrivée);
            try {
                Signature signeur = Signature.getInstance("DSA");
                signeur.initSign(clefPrivée);
                try ( FileInputStream fis = new FileInputStream("./src/DSA/Releve.pdf") ) {
                    byte[] buffer = new byte[1024];
                    int nbOctetsLus;
                    while ((nbOctetsLus = fis.read(buffer)) != -1) {
                        signeur.update(buffer, 0, nbOctetsLus);
                    }
                }
                byte[] appendice = signeur.sign();
                System.out.println("L'appendice est : " + toHex(appendice));
                writeAppendice("./src/DSA/appendice.bin", appendice);
             } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
                System.out.println("Impossible de signer le document!");
            }
                
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Impossible de fabriquer la clef DSA!");
        }
            
    }

    public static String toHex(byte[] donnees) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i != donnees.length; i++) {
            if (i>0) buf.append(", ");
            buf.append("0x");
            buf.append(String.format("%02X", donnees[i]));
        }
        buf.append(" ("+ donnees.length + " octets) ");
        return buf.toString();
    }

    public static void writeAppendice(String outputFile, byte[] appendice) {
        try {
            FileOutputStream fos = new FileOutputStream(outputFile);
            fos.write(appendice);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}

/*
  $ make
  $ java SignatureDSA
  L'appendice est : 0x30, 0x2D, 0x02, 0x15, 0x00, 0xA9, 0x20, 0x6F, 0x0E, 0xC9, 0xED, 0x91, 0xC3, 0xF9, 0x8D, 0x50, 0x8A, 0x27, 0x2D, 0xF9, 0x19, 0x78, 0xD5, 0xD5, 0xFA, 0x02, 0x14, 0x4C, 0x24, 0x20, 0x89, 0xAE, 0x6B, 0x1B, 0xC9, 0x00, 0x9B, 0xDF, 0xC4, 0x6D, 0xC2, 0x8C, 0xAE, 0xFA, 0x77, 0x9B, 0xA2 (47 octets) 
  $ java SignatureDSA
  L'appendice est : 0x30, 0x2C, 0x02, 0x14, 0x6E, 0x76, 0xC4, 0x4B, 0x51, 0x66, 0xFE, 0x1B, 0x14, 0x3E, 0x46, 0x3A, 0x7F, 0x80, 0x89, 0xC0, 0xE0, 0xD2, 0x24, 0x0F, 0x02, 0x14, 0x08, 0xEB, 0xBC, 0x72, 0x36, 0x48, 0x75, 0xB1, 0xBB, 0x93, 0x08, 0x89, 0x8B, 0x8A, 0xFB, 0xD6, 0x52, 0x28, 0x9B, 0x4F (46 octets) 
  $ java SignatureDSA
  L'appendice est : 0x30, 0x2E, 0x02, 0x15, 0x00, 0xAC, 0x84, 0x08, 0xEA, 0x3F, 0x92, 0x5F, 0xCA, 0x77, 0x04, 0xA6, 0xC9, 0xB5, 0xB6, 0xFE, 0x18, 0xB9, 0xF2, 0xEB, 0x79, 0x02, 0x15, 0x00, 0x83, 0x36, 0x20, 0xE7, 0x90, 0x75, 0x9F, 0x6D, 0xE1, 0x21, 0x6F, 0xAA, 0x14, 0x74, 0x2C, 0xA5, 0x02, 0x37, 0x27, 0xB6 (48 octets) 
  $ 
*/

