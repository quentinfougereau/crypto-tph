package DSA;

import java.math.BigInteger;

import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.io.*;

public class MesClefsDSA {
    public static void main(String[] args) {
        SecureRandom alea = new SecureRandom();
	    try{
            KeyPairGenerator forge = KeyPairGenerator.getInstance("DSA");
            forge.initialize(1024);
            KeyPair paireDeClefs = forge.generateKeyPair();        
            DSAPublicKey clefPublique = (DSAPublicKey) paireDeClefs.getPublic();
            DSAPrivateKey clefPrivée = (DSAPrivateKey) paireDeClefs.getPrivate();
            System.out.println("Clef privée au format: " + clefPrivée.getFormat());
            System.out.println("Clef publique au format: " + clefPublique.getFormat());
            DSAParams paramètres = clefPrivée.getParams();
            BigInteger g = paramètres.getG();
            BigInteger p = paramètres.getP();
            BigInteger q = paramètres.getQ();
            BigInteger x = clefPrivée.getX();
            BigInteger y = clefPublique.getY();
            System.out.println("Paramètres de la paire de clefs DSA: ");
            System.out.println("   p = 0x" + p.toString(16));
            System.out.println("   q = 0x" + q.toString(16));
            System.out.println("   g = 0x" + g.toString(16));
            System.out.println("   x = 0x" + x.toString(16));
            System.out.println("   y = 0x" + y.toString(16));
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Impossible de fabriquer la paire de clefs DSA");
        }            
    }
}

/*
  $ java MesClefsDSA
  Clef privée au format: PKCS#8
  Clef publique au format: X.509
  Paramètres de la paire de clefs DSA: 
  p = 0xfd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7
  q = 0x9760508f15230bccb292b982a2eb840bf0581cf5
  g = 0xf7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a
  x = 0x8a97e0534ee7230cf6a7a936d4a3abf83009e1b5
  y = 0x12eccb89bdf5350be84096a29f9593334dff1ec9130626faf453ba42a9816f4388dc4684cbb5ad00ec86788dcc74e6fd67d9b2d204353a559d4da016d1fff3c48d6567ef5866e0583bc3d696174108ebf8a68b89deae8407363385f7a4d10ad24c3320933e867c05d6a3dae2f556fc7106109f3bc7e80750788ef648f61d4a1b
  $ java MesClefsDSA
  Clef privée au format: PKCS#8
  Clef publique au format: X.509
  Paramètres de la paire de clefs DSA: 
  p = 0xfd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7
  q = 0x9760508f15230bccb292b982a2eb840bf0581cf5
  g = 0xf7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a
  x = 0x642f1475271fa0671005b1d266d5b89945ef4ebe
  y = 0xa50e11546f0fc3b6ccd191439ba724a517ea10f7c50012b689c0220ab8618eff45da9e20210a1a475cdb2e72e97439f7f73758ef81e7ad453d8a3079221902c17d0e1f5036325a40f471120d0bc066be9b92000e84e1b83b0ed6c729e48b839a37e21925de5ac5f3ce1e3cec1a99e40b0226c6e88293957995f3fb41172a63ef
 */
