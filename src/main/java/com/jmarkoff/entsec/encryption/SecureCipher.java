/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package com.jmarkoff.entsec.encryption;

import android.security.keystore.KeyProperties;
import android.util.Log;
import android.util.Pair;

import com.jmarkoff.entsec.SecureConfig;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class SecureCipher {

    private SecureConfig secureConfig;

    private static final String TAG = "SecureCipher";

    public static SecureCipher getDefault() {
        return new SecureCipher(SecureConfig.getStrongConfig());
    }

    public static SecureCipher getInstance(SecureConfig secureConfig) {
        return new SecureCipher(secureConfig);
    }

    private SecureCipher(SecureConfig secureConfig) {
        this.secureConfig = secureConfig;
    }

    public enum SecureFileEncodingType {
        SYMMETRIC(0),
        ASYMMETRIC(1),
        EPHEMERAL(2),
        NOT_ENCRYPTED(1000);

        private final int type;

        SecureFileEncodingType(int type) {
            this.type = type;
        }

        public int getType() {
            return this.type;
        }

        public static SecureFileEncodingType fromId(int id) {
            switch (id) {
                case 0:
                    return SYMMETRIC;
                case 1:
                    return ASYMMETRIC;
                case 2:
                    return EPHEMERAL;
            }
            return NOT_ENCRYPTED;
        }

    }


    /**
     * Encrypts data with an existing key alias from the AndroidKeyStore.
     *
     * @param keyAlias  The name of the existing SecretKey to retrieve from the AndroidKeyStore.
     * @param clearData The unencrypted data to encrypt
     * @return A Pair of byte[]'s, first is the encrypted data, second is the IV (initialization vector)
     * used to encrypt which is required for decryption
     */
    public Pair<byte[], byte[]> encryptSensitiveData(String keyAlias, byte[] clearData) {
        try {
            KeyStore keyStore = KeyStore.getInstance(secureConfig.getAndroidKeyStore());
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(keyAlias, null);
            Cipher cipher = Cipher.getInstance(secureConfig.getSymmetricCipherTransformation());
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] iv = cipher.getIV();
            return new Pair<>(cipher.doFinal(clearData), cipher.getIV());
        } catch (GeneralSecurityException ex) {
            throw new SecurityException(ex);
        } catch (IOException ex) {
            throw new SecurityException(ex);
        }
    }

    /**
     * Encrypts data with a public key from the cert in the AndroidKeyStore.
     *
     * @param keyAlias  The name of the existing KeyPair to retrieve the PublicKey from the AndroidKeyStore.
     * @param clearData The unencrypted data to encrypt
     * @return A Pair of byte[]'s, first is the encrypted data, second is the IV (initialization vector)
     * used to encrypt which is required for decryption
     */
    public byte[] encryptSensitiveDataAsymmetric(String keyAlias, byte[] clearData) {
        try {
            KeyStore keyStore = KeyStore.getInstance(secureConfig.getAndroidKeyStore());
            keyStore.load(null);
            PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();
            Cipher cipher = Cipher.getInstance(secureConfig.getAsymmetricCipherTransformation());
            if (secureConfig.getAsymmetricPaddings().equals(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)) {
                cipher.init(Cipher.ENCRYPT_MODE, publicKey, new OAEPParameterSpec("SHA-256",
                        "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT));
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            }
            return cipher.doFinal(clearData);
        } catch (GeneralSecurityException ex) {
            throw new SecurityException(ex);
        } catch (IOException ex) {
            throw new SecurityException(ex);
        }
    }

    /**
     * Encrypts data using an Ephemeral key, destroying any trace of the key from the Cipher used.
     *
     * @param ephemeralSecretKey The generated Ephemeral key
     * @param clearData          The unencrypted data to encrypt
     * @return A Pair of byte[]'s, first is the encrypted data, second is the IV (initialization vector)
     * used to encrypt which is required for decryption
     */
    public Pair<byte[], byte[]> encryptEphemeralData(EphemeralSecretKey
                                                             ephemeralSecretKey, byte[] clearData) {
        try {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            byte[] iv = new byte[SecureConfig.AES_IV_SIZE_BYTES];
            secureRandom.nextBytes(iv);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(secureConfig.getSymmetricGcmTagLength(), iv);
            final Cipher cipher = Cipher.getInstance(secureConfig.getSymmetricCipherTransformation());
            cipher.init(Cipher.ENCRYPT_MODE, ephemeralSecretKey, parameterSpec);
            byte[] encryptedData = cipher.doFinal(clearData);
            ephemeralSecretKey.destroyCipherKey(cipher, Cipher.ENCRYPT_MODE);
            return new Pair<>(encryptedData, iv);
        } catch (GeneralSecurityException ex) {
            throw new SecurityException(ex);
        }
    }

    /**
     * Decrypts a previously encrypted byte[]
     * <p>
     * Destroys all traces of the key data in the Cipher.
     *
     * @param ephemeralSecretKey   The generated Ephemeral key
     * @param encryptedData        The byte[] of encrypted data
     * @param initializationVector The IV of which the encrypted data was encrypted with
     * @return The byte[] of data that has been decrypted
     */
    public byte[] decryptEphemeralData(EphemeralSecretKey ephemeralSecretKey,
                                       byte[] encryptedData, byte[] initializationVector) {
        try {
            final Cipher cipher = Cipher.getInstance(secureConfig.getSymmetricCipherTransformation());
            cipher.init(Cipher.DECRYPT_MODE, ephemeralSecretKey, new GCMParameterSpec(secureConfig.getSymmetricGcmTagLength(), initializationVector));
            byte[] decryptedData = cipher.doFinal(encryptedData);
            ephemeralSecretKey.destroyCipherKey(cipher, Cipher.DECRYPT_MODE);
            return decryptedData;
        } catch (GeneralSecurityException ex) {
            throw new SecurityException(ex);
        }
    }

    /**
     * Decrypts a previously encrypted byte[]
     *
     * @param keyAlias             The name of the existing SecretKey to retrieve from the AndroidKeyStore.
     * @param encryptedData        The byte[] of encrypted data
     * @param initializationVector The IV of which the encrypted data was encrypted with
     * @return The byte[] of data that has been decrypted
     */
    public byte[] decryptSensitiveData(String keyAlias, byte[] encryptedData,
                                       byte[] initializationVector) {
        byte[] decryptedData = new byte[0];
        try {
            KeyStore keyStore = KeyStore.getInstance(secureConfig.getAndroidKeyStore());
            keyStore.load(null);
            Key key = keyStore.getKey(keyAlias, null);
            Cipher cipher = Cipher.getInstance(secureConfig.getSymmetricCipherTransformation());
            GCMParameterSpec spec = new GCMParameterSpec(secureConfig.getSymmetricGcmTagLength(), initializationVector);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            decryptedData = cipher.doFinal(encryptedData);
        } catch (GeneralSecurityException ex) {
            throw new SecurityException(ex);
        } catch (IOException ex) {
            throw new SecurityException(ex);
        }
        return decryptedData;
    }

    /**
     * Decrypts a previously encrypted byte[] with the PrivateKey
     *
     * @param keyAlias      The name of the existing KeyPair to retrieve from the AndroidKeyStore.
     * @param encryptedData The byte[] of encrypted data
     * @return The byte[] of data that has been decrypted
     */
    public byte[] decryptSensitiveDataAsymmetric(String keyAlias, byte[] encryptedData) {
        byte[] decryptedData = new byte[0];
        try {
            KeyStore keyStore = KeyStore.getInstance(secureConfig.getAndroidKeyStore());
            keyStore.load(null);
            PrivateKey key = (PrivateKey) keyStore.getKey(keyAlias, null);
            Cipher cipher = Cipher.getInstance(secureConfig.getAsymmetricCipherTransformation());
            if (secureConfig.getAsymmetricPaddings().equals(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)) {
                cipher.init(Cipher.DECRYPT_MODE, key, new OAEPParameterSpec("SHA-256",
                        "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT));
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key);
            }
            decryptedData = cipher.doFinal(encryptedData);
        } catch (GeneralSecurityException ex) {
            ex.printStackTrace();
            //Log.e(TAG, ex.getMessage());
            return decryptedData;
        } catch (IOException ex) {
            Log.e(TAG, ex.getMessage());
            ex.printStackTrace();
            return decryptedData;
        }
        return decryptedData;
    }

    public byte[] encodeEphemeralData(byte[] keyPairAlias, byte[] encryptedKey,
                                      byte[] cipherText, byte[] iv) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(((Integer.SIZE / 8) * 4) + iv.length +
                keyPairAlias.length + encryptedKey.length + cipherText.length);
        byteBuffer.putInt(SecureFileEncodingType.EPHEMERAL.getType());
        byteBuffer.putInt(encryptedKey.length);
        byteBuffer.put(encryptedKey);
        byteBuffer.putInt(iv.length);
        byteBuffer.put(iv);
        byteBuffer.putInt(keyPairAlias.length);
        byteBuffer.put(keyPairAlias);
        byteBuffer.put(cipherText);
        return byteBuffer.array();
    }

    public byte[] encodeSymmetricData(byte[] keyAlias, byte[] cipherText, byte[] iv) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(((Integer.SIZE / 8) * 3) + iv.length +
                keyAlias.length + cipherText.length);
        byteBuffer.putInt(SecureFileEncodingType.SYMMETRIC.getType());
        byteBuffer.putInt(iv.length);
        byteBuffer.put(iv);
        byteBuffer.putInt(keyAlias.length);
        byteBuffer.put(keyAlias);
        byteBuffer.put(cipherText);
        return byteBuffer.array();
    }

    public byte[] encodeAsymmetricData(byte[] keyPairAlias, byte[] cipherText) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(((Integer.SIZE / 8) * 2) +
                keyPairAlias.length + cipherText.length);
        byteBuffer.putInt(SecureFileEncodingType.ASYMMETRIC.getType());
        byteBuffer.putInt(keyPairAlias.length);
        byteBuffer.put(keyPairAlias);
        byteBuffer.put(cipherText);
        return byteBuffer.array();
    }

    public byte[] decryptEncodedData(byte[] encodedCipherText) {
        byte[] decryptedData = null;
        ByteBuffer byteBuffer = ByteBuffer.wrap(encodedCipherText);
        int encodingTypeVal = byteBuffer.getInt();
        SecureFileEncodingType encodingType = SecureFileEncodingType.fromId(encodingTypeVal);
        byte[] encodedEphKey = null;
        byte[] iv = null;
        String keyAlias = null;
        byte[] cipherText = null;

        switch (encodingType) {
            case EPHEMERAL:
                int encodedEphKeyLength = byteBuffer.getInt();
                encodedEphKey = new byte[encodedEphKeyLength];
                byteBuffer.get(encodedEphKey);
            case SYMMETRIC:
                int ivLength = byteBuffer.getInt();
                iv = new byte[ivLength];
                byteBuffer.get(iv);
            case ASYMMETRIC:
                int keyAliasLength = byteBuffer.getInt();
                byte[] keyAliasBytes = new byte[keyAliasLength];
                byteBuffer.get(keyAliasBytes);
                keyAlias = new String(keyAliasBytes);
                cipherText = new byte[byteBuffer.remaining()];
                byteBuffer.get(cipherText);
                break;
            case NOT_ENCRYPTED:
                throw new SecurityException("File not encrypted.");
        }
        switch (encodingType) {
            case EPHEMERAL:
                byte[] decryptedEphKey = decryptSensitiveDataAsymmetric(keyAlias, encodedEphKey);
                EphemeralSecretKey ephemeralSecretKey = new EphemeralSecretKey(decryptedEphKey);
                decryptedData = decryptEphemeralData(
                        ephemeralSecretKey,
                        cipherText, iv);
                ephemeralSecretKey.destroy();
                break;
            case SYMMETRIC:
                decryptedData = decryptSensitiveData(
                        keyAlias,
                        cipherText, iv);
                break;
            case ASYMMETRIC:
                decryptedData = decryptSensitiveDataAsymmetric(
                        keyAlias,
                        cipherText);
                break;
            case NOT_ENCRYPTED:
                throw new SecurityException("File not encrypted.");
        }
        return decryptedData;
    }


}
