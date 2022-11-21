package com.bosa.esealing.service;

import com.bosa.esealing.model.Digest;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;

import java.io.FileInputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.Enumeration;

public class SadUtil {
    public static String makeSAD(Digest documentDigests) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("../SetupHSM/sealing_sad.p12"), "123456".toCharArray());
        Enumeration<String> aliases = ks.aliases();
        PrivateKey sadSignKey = null;
        X509Certificate sadSignCert = null;
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)
                        ks.getEntry(alias, new KeyStore.PasswordProtection("123456".toCharArray()));
                sadSignKey = entry.getPrivateKey();
                sadSignCert = (X509Certificate) (entry.getCertificateChain())[0];
                break;
            }
        }

        // Serialize the documentDigests to json, this is the JWS header
        ObjectMapper objectMapper = new ObjectMapper();
        StringWriter out = new StringWriter();
        objectMapper.writeValue(out, documentDigests);
        String sadData = out.toString();

        // Create the JWS header,
        // the kid (key id) value = the certificate serial number, hex encoded (no capitals)
        String sadSigSerialNr = sadSignCert.getSerialNumber().toString(16);
        System.out.println("SAD Serial number: " + sadSigSerialNr);

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES384).keyID(sadSigSerialNr).build(),
                new Payload(sadData));

        // Sign the JWS
        jwsObject.sign(new ECDSASigner((ECPrivateKey) sadSignKey));
        String sad = jwsObject.serialize();

        return sad;
    }
}
