package DSA;

import java.io.*;
import java.math.*;
import java.security.*;
import java.security.interfaces.*;

import java.security.spec.*;

class MaClefDSA {

    public static void main(String[] args) {
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


        /* A compléter à l'aide des méthodes de la classe BigInteger */
        System.out.println("Est une paire de clefs DSA : " + isDSAKeyPair(p, q, g, x, y));
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

    public static boolean est_probablement_premier(BigInteger n) {
        /*
          Modifiez cette fonction afin qu'elle retourne si oui
          ou non l'entier n est un nombre premier, avec un taux
          d'erreur inférieur à 1/1000 000 000 000 000 000.
        */
        int c = (int) Math.round(15 * (Math.log(10) / Math.log(2)));
        return n.isProbablePrime(c);
    }

    public static boolean isDSAKeyPair(BigInteger p, BigInteger q, BigInteger g, BigInteger x, BigInteger y) {
        if (est_probablement_premier(p) && p.bitLength() == 1024) {
            if (est_probablement_premier(q) && q.bitLength() == 160) {
                if (((p.subtract(BigInteger.ONE)).mod(q)).equals(BigInteger.ZERO)) {
                    if (g.compareTo(BigInteger.TWO) == 1 && g.compareTo(p.subtract(BigInteger.ONE)) == -1) {
                        if (g.modPow(q, p).equals(BigInteger.ONE)) {
                            if (q.compareTo(x) == 1 && g.modPow(x, p).equals(y)) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

}

