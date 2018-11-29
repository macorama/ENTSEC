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

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.jmarkoff.entsec.SecureConfig;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;

public class SecureKeyGenerator {

    private SecureConfig secureConfig;

    public static SecureKeyGenerator getDefault() {
        return new SecureKeyGenerator(SecureConfig.getStrongConfig());
    }

    public static SecureKeyGenerator getInstance(SecureConfig secureConfig) {
        return new SecureKeyGenerator(secureConfig);
    }

    private SecureKeyGenerator(SecureConfig secureConfig) {
        this.secureConfig = secureConfig;
    }

    /**
     * <p>
     * Generates a sensitive data key and adds the SecretKey to the AndroidKeyStore.
     * Utilizes UnlockedDeviceProtection to ensure that the device must be unlocked in order to
     * use the generated key.
     * </p>
     *
     * @param keyAlias The name of the generated SecretKey to save into the AndroidKeyStore.
     * @return true if the key was generated, false otherwise
     */
    //@TargetApi(Build.VERSION_CODES.P)
    public boolean generateSymmetricKey(String keyAlias) {
        boolean created = false;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(secureConfig.getSymmetricKeyAlgorithm(), secureConfig.getAndroidKeyStore());
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    keyAlias, secureConfig.getSymmetricKeyPurposes()).
                    setBlockModes(secureConfig.getSymmetricBlockModes()).
                    setEncryptionPaddings(secureConfig.getSymmetricPaddings()).
                    setKeySize(secureConfig.getSymmetricKeySize());
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder = builder.setUnlockedDeviceRequired(secureConfig.isSymmetricSensitiveDataProtectionEnabled());
            }
            keyGenerator.init(builder.build());
            keyGenerator.generateKey();
            created = true;
        } catch (NoSuchAlgorithmException ex) {
            throw new SecurityException(ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new SecurityException(ex);
        } catch (NoSuchProviderException ex) {
            throw new SecurityException(ex);
        }
        return created;
    }

    /**
     * <p>
     * Generates a sensitive data public/private key pair and adds the KeyPair to the AndroidKeyStore.
     * Utilizes UnlockedDeviceProtection to ensure that the device must be unlocked in order to
     * use the generated key.
     * </p>
     * <p>
     * ANDROID P ONLY (API LEVEL 28>)
     * </p>
     *
     * @param keyPairAlias The name of the generated SecretKey to save into the AndroidKeyStore.
     * @return true if the key was generated, false otherwise
     */
    //@TargetApi(Build.VERSION_CODES.P)
    public boolean generateAsymmetricKeyPair(String keyPairAlias) {
        boolean created = false;
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(secureConfig.getAsymmetricKeyPairAlgorithm(), secureConfig.getAndroidKeyStore());
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    keyPairAlias, secureConfig.getAsymmetricKeyPurposes())
                    .setEncryptionPaddings(secureConfig.getAsymmetricPaddings())
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setBlockModes(secureConfig.getAsymmetricBlockModes())
                    .setKeySize(secureConfig.getAsymmetricKeySize());
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder = builder.setUnlockedDeviceRequired(secureConfig.isAsymmetricSensitiveDataProtectionEnabled());
            }
            keyGenerator.initialize(builder.build());
            keyGenerator.generateKeyPair();
            created = true;
        } catch (NoSuchAlgorithmException ex) {
            throw new SecurityException(ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new SecurityException(ex);
        } catch (NoSuchProviderException ex) {
            throw new SecurityException(ex);
        }
        return created;
    }

    /**
     * <p>
     * Generates an Ephemeral symmetric key that can be fully destroyed and removed from memory.
     * </p>
     *
     * @return The EphemeralSecretKey generated
     */
    public EphemeralSecretKey generateEphemeralDataKey() {
        try {
            SecureRandom secureRandom;
            if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.O){
                secureRandom = SecureRandom.getInstanceStrong();
            } else {
                // Not best practices, TODO update this as per this SO thread
                // https://stackoverflow.com/questions/36813098/securerandom-provider-crypto-unavailable-in-android-n-for-deterministially-gen
                secureRandom = new SecureRandom();
            }
            byte[] key = new byte[secureConfig.getSymmetricKeySize() / 8];
            secureRandom.nextBytes(key);
            return new EphemeralSecretKey(key, secureConfig.getSymmetricKeyAlgorithm());
        } catch (GeneralSecurityException ex) {
            throw new SecurityException(ex);
        }
    }

}
