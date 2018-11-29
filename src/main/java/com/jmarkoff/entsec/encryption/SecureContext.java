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

import android.app.KeyguardManager;
import android.content.Context;
import android.support.annotation.NonNull;
import android.util.Pair;

import com.jmarkoff.entsec.SecureConfig;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.util.Arrays;

public class SecureContext {

    private static final String TAG = "SecureContext";

    private Context context;
    private SecureConfig secureConfig;

    public SecureContext(Context context) {
        this(context, SecureConfig.getStrongConfig());
    }

    public SecureContext(Context context, SecureConfig secureConfig) {
        this.context = context;
        this.secureConfig = secureConfig;
    }

    public FileInputStream openEncryptedFileInput(String name) throws FileNotFoundException, SecurityException {
        if (secureConfig.isAsymmetricSensitiveDataProtectionEnabled() && deviceLocked()) {
            throw new SecurityException("Cannot access file " + name + ". Please unlock your device.");
        }
        return new EncryptedFileInputStream(name, context.openFileInput(name));
    }

    public FileOutputStream openEncryptedFileOutput(String name, int mode, String keyPairAlias) throws FileNotFoundException {
        return new EncryptedFileOutputStream(name, keyPairAlias, context.openFileOutput(name, mode));
    }

    public boolean deviceLocked() {
        KeyguardManager keyGuardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        return keyGuardManager.isDeviceLocked();
    }

    class EncryptedFileOutputStream extends FileOutputStream {

        private FileOutputStream fileOutputStream;
        private String keyPairAlias;

        public EncryptedFileOutputStream(String name, String keyPairAlias, FileOutputStream fileOutputStream) {
            super(new FileDescriptor());
            this.keyPairAlias = keyPairAlias;
            this.fileOutputStream = fileOutputStream;
        }

        public EncryptedFileOutputStream(@NonNull String name) throws FileNotFoundException {
            super(name);
            throw new UnsupportedOperationException("This class can only be instantiated from an existing FileOutputStream.");
        }

        public EncryptedFileOutputStream(@NonNull String name, boolean append) throws FileNotFoundException {
            super(name, append);
            throw new UnsupportedOperationException("This class can only be instantiated from an existing FileOutputStream.");
        }

        public EncryptedFileOutputStream(@NonNull File file) throws FileNotFoundException {
            super(file);
            throw new UnsupportedOperationException("This class can only be instantiated from an existing FileOutputStream.");
        }

        public EncryptedFileOutputStream(@NonNull File file, boolean append) throws FileNotFoundException {
            super(file, append);
            throw new UnsupportedOperationException("This class can only be instantiated from an existing FileOutputStream.");
        }

        public EncryptedFileOutputStream(@NonNull FileDescriptor fdObj) {
            super(fdObj);
            throw new UnsupportedOperationException("This class can only be instantiated from an existing FileOutputStream.");
        }

        private String getAsymKeyPairAlias() {
            return this.keyPairAlias;
        }

        @Override
        public void write(@NonNull byte[] b) throws IOException {
            SecureKeyStore secureKeyStore = SecureKeyStore.getDefault();
            if (!secureKeyStore.keyExists(getAsymKeyPairAlias())) {
                SecureKeyGenerator keyGenerator = SecureKeyGenerator.getDefault();
                keyGenerator.generateAsymmetricKeyPair(getAsymKeyPairAlias());
            }
            SecureKeyGenerator secureKeyGenerator = SecureKeyGenerator.getDefault();
            EphemeralSecretKey secretKey = secureKeyGenerator.generateEphemeralDataKey();
            SecureCipher secureCipher = SecureCipher.getDefault();
            Pair<byte[], byte[]> encryptedData = secureCipher.encryptEphemeralData(secretKey, b);
            byte[] encryptedEphemeralKey = secureCipher.encryptSensitiveDataAsymmetric(getAsymKeyPairAlias(), secretKey.getEncoded());
            byte[] encodedData = secureCipher.encodeEphemeralData(getAsymKeyPairAlias().getBytes(), encryptedEphemeralKey, encryptedData.first, encryptedData.second);
            secretKey.destroy();
            fileOutputStream.write(encodedData);
        }

        @Override
        public void write(int b) throws IOException {
            throw new UnsupportedOperationException("For encrypted files, you must write all data simultaneously. Call #write(byte[]).");
        }

        @Override
        public void write(@NonNull byte[] b, int off, int len) throws IOException {
            throw new UnsupportedOperationException("For encrypted files, you must write all data simultaneously. Call #write(byte[]).");
        }

        @Override
        public void close() throws IOException {
            fileOutputStream.close();
        }

        @NonNull
        @Override
        public FileChannel getChannel() {
            throw new UnsupportedOperationException("For encrypted files, you must write all data simultaneously. Call #write(byte[]).");
        }

        @Override
        protected void finalize() throws IOException {
            super.finalize();
        }

        @Override
        public void flush() throws IOException {
            fileOutputStream.flush();
        }
    }

    class EncryptedFileInputStream extends FileInputStream {

        private FileInputStream fileInputStream;
        private byte[] decryptedData;
        private int readStatus = 0;

        public EncryptedFileInputStream(String name, FileInputStream fileInputStream) throws FileNotFoundException {
            super(new FileDescriptor());
            this.fileInputStream = fileInputStream;
        }

        public EncryptedFileInputStream(@NonNull String name) throws FileNotFoundException {
            super(name);
            throw new UnsupportedOperationException("This class can only be instantiated from an existing FileInputStream.");
        }

        public EncryptedFileInputStream(@NonNull File file) throws FileNotFoundException {
            super(file);
            throw new UnsupportedOperationException("This class can only be instantiated from an existing FileInputStream.");
        }

        public EncryptedFileInputStream(@NonNull FileDescriptor fdObj) {
            super(fdObj);
            throw new UnsupportedOperationException("This class can only be instantiated from an existing FileInputStream.");
        }

        @Override
        public int read() throws IOException {
            throw new UnsupportedOperationException("For encrypted files, you must read all data simultaneously. Call #read(byte[]).");
        }

        private void decrypt() throws IOException {
            if (this.decryptedData == null) {
                byte[] encodedData = new byte[fileInputStream.available()];
                readStatus = fileInputStream.read(encodedData);
                SecureCipher secureCipher = SecureCipher.getDefault();
                this.decryptedData = secureCipher.decryptEncodedData(encodedData);
            }
        }

        private void destroyCache() {
            if (decryptedData != null) {
                Arrays.fill(decryptedData, (byte) 0);
                decryptedData = null;
            }
        }

        @Override
        public int read(@NonNull byte[] b) throws IOException {
            decrypt();
            System.arraycopy(decryptedData, 0, b, 0, decryptedData.length);
            return readStatus;
        }

        @Override
        public int read(@NonNull byte[] b, int off, int len) throws IOException {
            throw new UnsupportedOperationException("For encrypted files, you must read all data simultaneously. Call #read(byte[]).");
        }

        @Override
        public long skip(long n) throws IOException {
            throw new UnsupportedOperationException("For encrypted files, you must read all data simultaneously. Call #read(byte[]).");
        }

        @Override
        public int available() throws IOException {
            decrypt();
            return decryptedData.length;
        }

        @Override
        public void close() throws IOException {
            destroyCache();
            fileInputStream.close();
        }

        @Override
        public FileChannel getChannel() {
            throw new UnsupportedOperationException("For encrypted files, you must read all data simultaneously. Call #read(byte[]).");
        }

        @Override
        protected void finalize() throws IOException {
            destroyCache();
            super.finalize();
        }

        @Override
        public synchronized void mark(int readlimit) {
            throw new UnsupportedOperationException("For encrypted files, you must read all data simultaneously. Call #read(byte[]).");
        }

        @Override
        public synchronized void reset() throws IOException {
            throw new UnsupportedOperationException("For encrypted files, you must read all data simultaneously. Call #read(byte[]).");
        }

        @Override
        public boolean markSupported() {
            return false;
        }
    }

}
