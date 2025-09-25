package com.mendix.cloud.urlsign.util;

import com.mendix.cloud.urlsign.exception.URLSignException;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.io.BufferedReader;
import java.util.Base64;
import java.util.regex.Pattern;

public class KeyImporter {

    private static final Pattern PEM_KEY_PATTERN = Pattern.compile(
        "(?s)-----BEGIN (RSA )?(PRIVATE|PUBLIC) KEY-----.*?-----END (RSA )?(PRIVATE|PUBLIC) KEY-----"
    );
    private static final Pattern SSH_PUB_KEY_PATTERN = Pattern.compile("^ssh-rsa\\s+.+$");
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private KeyImporter(){
    }

    public static PrivateKey importPrivateKey(byte[] privateKeyBytes) throws URLSignException {
        if (privateKeyBytes == null || privateKeyBytes.length == 0) {
            throw new URLSignException("Private key data is empty or null");
        }

        try {
            // Try PKCS#8 format first (most common)
            try {
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
                return KeyFactory.getInstance("RSA").generatePrivate(spec);
            } catch (InvalidKeySpecException e) {
                // Try PKCS#1 format by converting it to PKCS#8
                try {
                    // This is a PKCS#1 key in DER format
                    ASN1Sequence seq = ASN1Sequence.getInstance(privateKeyBytes);
                    PrivateKeyInfo keyInfo = new PrivateKeyInfo(
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                            org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.rsaEncryption,
                            null
                        ),
                        seq
                    );
                    return KeyFactory.getInstance("RSA").generatePrivate(
                        new PKCS8EncodedKeySpec(keyInfo.getEncoded())
                    );
                } catch (Exception e1) {
                    throw new URLSignException("Failed to load private key. Unsupported key format.", e1);
                }
            }
        } catch (Exception e) {
            throw new URLSignException("Failed to import private key: " + e.getMessage(), e);
        }
    }

    public static PrivateKey importPrivateKey(String privateKey) throws URLSignException {
        if (privateKey == null || privateKey.trim().isEmpty()) {
            throw new URLSignException("Private key string is empty or null");
        }

        try {
            // Handle PEM format
            if (PEM_KEY_PATTERN.matcher(privateKey).find()) {
                // Clean up the key string
                String cleanKey = privateKey
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "")
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
                
                byte[] keyBytes = Base64.getDecoder().decode(cleanKey);
                return importPrivateKey(keyBytes);
            }
            // Handle raw base64
            else if (privateKey.matches("^[A-Za-z0-9+/=]+$")) {
                return importPrivateKey(Base64.getDecoder().decode(privateKey));
            } else {
                throw new URLSignException("Unsupported private key format");
            }
        } catch (IllegalArgumentException e) {
            throw new URLSignException("Invalid base64 encoding in private key", e);
        } catch (Exception e) {
            throw new URLSignException("Failed to parse private key: " + e.getMessage(), e);
        }
    }

    public static PrivateKey importPrivateKey(File privateKeyFile) throws URLSignException {
        if (privateKeyFile == null || !privateKeyFile.exists() || !privateKeyFile.canRead()) {
            throw new URLSignException("Private key file is not accessible: " + 
                (privateKeyFile != null ? privateKeyFile.getAbsolutePath() : "null"));
        }

        try (FileReader fileReader = new FileReader(privateKeyFile);
             BufferedReader bufferedReader = new BufferedReader(fileReader)) {
            
            StringBuilder keyContent = new StringBuilder();
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                keyContent.append(line).append("\n");
            }
            
            return importPrivateKey(keyContent.toString());
        } catch (IOException e) {
            throw new URLSignException("Failed to read private key file: " + e.getMessage(), e);
        }
    }

    private static PrivateKey readPrivateKey(File privateKeyFile) throws URLSignException, IOException {
        try (PEMParser pemParser = new PEMParser(new FileReader(privateKeyFile))) {
            Object object = pemParser.readObject();
            
            if (object instanceof PEMKeyPair) {
                PEMKeyPair keyPair = (PEMKeyPair) object;
                return new JcaPEMKeyConverter()
                    .setProvider("BC")
                    .getKeyPair(keyPair)
                    .getPrivate();
            } else if (object instanceof PrivateKeyInfo) {
                return new JcaPEMKeyConverter()
                    .setProvider("BC")
                    .getPrivateKey((PrivateKeyInfo) object);
            } else {
                throw new URLSignException("Unsupported private key format in file: " + 
                    (object != null ? object.getClass().getName() : "null"));
            }
        } catch (Exception e) {
            throw new URLSignException("Failed to parse private key from file: " + e.getMessage(), e);
        }
    }

    /*
     * Heavily based on:
     * https://github.com/ragnar-johannsson/CloudStack/blob/master/utils/src/com/cloud/utils/crypt/RSAHelper.java
     */
    public static PublicKey importPublicKey(byte[] publicKeyBytes) throws URLSignException {
        if (publicKeyBytes == null || publicKeyBytes.length == 0) {
            throw new URLSignException("Public key data is empty or null");
        }

        try {
            // Try X.509 format first
            try {
                X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
                return KeyFactory.getInstance("RSA").generatePublic(spec);
            } catch (InvalidKeySpecException e) {
                // Try SSH format
                try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(publicKeyBytes))) {
                    byte[] header = readElement(dis);
                    String pubKeyFormat = new String(header, StandardCharsets.US_ASCII);
                    
                    if ("ssh-rsa".equals(pubKeyFormat)) {
                        byte[] publicExponent = readElement(dis);
                        byte[] modulus = readElement(dis);
                        
                        KeySpec spec = new RSAPublicKeySpec(
                            new BigInteger(1, modulus), 
                            new BigInteger(1, publicExponent)
                        );
                        return KeyFactory.getInstance("RSA").generatePublic(spec);
                    } else {
                        throw new URLSignException("Unsupported public key format: " + pubKeyFormat);
                    }
                } catch (IOException e1) {
                    throw new URLSignException("Failed to read public key data", e1);
                }
            }
        } catch (Exception e) {
            throw new URLSignException("Failed to import public key: " + e.getMessage(), e);
        }
    }

    public static PublicKey importPublicKey(String publicKey) throws URLSignException {
        if (publicKey == null || publicKey.trim().isEmpty()) {
            throw new URLSignException("Public key string is empty or null");
        }

        try {
            // Handle PEM format
            if (publicKey.contains("-----BEGIN")) {
                // Clean up the key string
                String cleanKey = publicKey
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replace("\n", "")
                    .replace("\r", "")
                    .trim();
                
                return importPublicKey(Base64.getDecoder().decode(cleanKey));
            }
            // Handle SSH format (ssh-rsa AAAA... comment)
            else if (publicKey.trim().startsWith("ssh-rsa")) {
                String[] parts = publicKey.trim().split("\\s+");
                if (parts.length >= 2) {
                    // Parse SSH public key format
                    byte[] keyBytes = Base64.getDecoder().decode(parts[1]);
                    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(keyBytes));
                    
                    // Read the key type (should be "ssh-rsa")
                    byte[] typeBytes = readElement(dis);
                    String keyType = new String(typeBytes, StandardCharsets.US_ASCII);
                    if (!"ssh-rsa".equals(keyType)) {
                        throw new URLSignException("Unsupported SSH key type: " + keyType);
                    }
                    
                    // Read the public exponent and modulus
                    byte[] publicExponent = readElement(dis);
                    byte[] modulus = readElement(dis);
                    
                    // Create RSA public key spec
                    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(
                        new BigInteger(1, modulus),
                        new BigInteger(1, publicExponent)
                    );
                    
                    // Generate and return the public key
                    return KeyFactory.getInstance("RSA").generatePublic(keySpec);
                }
            }
            // Try raw base64
            else if (publicKey.matches("^[A-Za-z0-9+/=]+$")) {
                return importPublicKey(Base64.getDecoder().decode(publicKey));
            }
            
            throw new URLSignException("Unsupported public key format");
        } catch (IllegalArgumentException e) {
            throw new URLSignException("Invalid base64 encoding in public key", e);
        } catch (Exception e) {
            throw new URLSignException("Failed to parse public key: " + e.getMessage(), e);
        }
    }

    public static PublicKey importPublicKey(File publicKeyFile) throws URLSignException {
        if (publicKeyFile == null || !publicKeyFile.exists() || !publicKeyFile.canRead()) {
            throw new URLSignException("Public key file is not accessible: " + 
                (publicKeyFile != null ? publicKeyFile.getAbsolutePath() : "null"));
        }
        
        try (BufferedReader reader = Files.newBufferedReader(publicKeyFile.toPath(), StandardCharsets.UTF_8)) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            return importPublicKey(content.toString());
        } catch (IOException e) {
            throw new URLSignException("Failed to read public key file: " + e.getMessage(), e);
        }
}

private static byte[] readElement(DataInputStream dis) throws IOException {
    int len = dis.readInt();
    if (len <= 0 || len > 8192) { // Reasonable upper limit
        throw new IOException("Invalid key data length: " + len);
    }
    byte[] buf = new byte[len];
    dis.readFully(buf);
    return buf;
}
}
