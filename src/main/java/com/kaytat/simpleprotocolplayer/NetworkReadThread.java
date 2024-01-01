/*
 * Copyright (C) 2011 The Android Open Source Project
 * Copyright (C) 2014 kaytat
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.kaytat.simpleprotocolplayer;

import android.util.Log;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Worker thread reads data from the network
 */
class NetworkReadThread extends ThreadStoppable {
    final String TAG;

    static final int[][] RETRY_PARAMS = new int[][]{{5, 12}, {20, 6}, {60, 2}};

    final WorkerThreadPair syncObject;
    final String ipAddr;
    final int port;
    final byte[] authenticationKey;
    final boolean attemptConnectionRetry;
    final byte[][] dataBuffer;
    final int numBuffers;
    int bufferIndex;

    // socket timeout at 5 seconds
    static final int SOCKET_TIMEOUT = 5 * 1000;

    public NetworkReadThread(WorkerThreadPair syncObject, String ipAddr, int port, byte[] authenticationKey,
                             boolean attemptConnectionRetry, String debugTag) {
        this.TAG = debugTag;
        this.setName(debugTag);
        this.syncObject = syncObject;
        this.ipAddr = ipAddr;
        this.port = port;
        this.authenticationKey = authenticationKey;
        this.attemptConnectionRetry = attemptConnectionRetry;

        // since we use BlockingQueue to pass data
        // so at most we will use NUM_PACKETS (in queue) + 1 (taken by
        // audioThread) +1 (read socket)
        // buffers .
        numBuffers = WorkerThreadPair.NUM_PACKETS + 2;
        bufferIndex = 0;
        dataBuffer = new byte[numBuffers][];
        for (int i = 0; i < numBuffers; i++) {
            dataBuffer[i] = new byte[syncObject.bytesPerAudioPacket];
        }
    }

    @Override
    public void run() {
        Log.i(TAG, "start");
        boolean connectionMade;
        int retryCount = 0;
        int retryParamIndex = 0;

        while (running) {
            connectionMade = runImpl();

            if (!running) {
                Log.i(TAG, "not running");
                break;
            }
            if (!attemptConnectionRetry) {
                Log.i(TAG, "no retries");
                break;
            }

            if (connectionMade) {
                retryCount = retryParamIndex = 0;
                continue;
            }

            // There was connection made.  Increment the counters.
            if (retryCount >= RETRY_PARAMS[retryParamIndex][1]) {
                retryCount = 0;
                retryParamIndex++;
                if (retryParamIndex >= RETRY_PARAMS.length) {
                    // Hit the limit.  Exit.
                    Log.i(TAG, "retry limit reached");
                    break;
                }
            }

            Log.d(TAG,
                    "retryCount:" + retryCount + " retryParamIndex:" + retryParamIndex);

            try {
                //noinspection BusyWait
                Thread.sleep((long) RETRY_PARAMS[retryParamIndex][0] * 1000);
            } catch (Exception e) {
                // Ignore.
            }
            retryCount++;
        }

        // Determine if cleanup is necessary
        if (running) {
            syncObject.brokenShutdown();
        }
        Log.i(TAG, "done");
    }

    public boolean runImpl() {
        Socket socket = null;
        boolean connectionMade = false;

        try {
            // Create the TCP socket and setup some parameters
            socket = new Socket(ipAddr, port);
            BufferedInputStream bufferedInputStream = new BufferedInputStream(socket.getInputStream());
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(socket.getOutputStream());
            DataInputStream dataInputStream = new DataInputStream(bufferedInputStream);
            DataOutputStream dataOutputStream = new DataOutputStream(bufferedOutputStream);
            socket.setSoTimeout(SOCKET_TIMEOUT);
            socket.setTcpNoDelay(true);

            Log.i(TAG, "running");

            int publicKeyBytesLength = dataInputStream.readInt();
            byte[] publicKeyBytes = new byte[publicKeyBytesLength];
            dataInputStream.readFully(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] secretKeyBytes = secretKey.getEncoded();
            Cipher publicKeyEncryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            publicKeyEncryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedSecretKeyBytes = publicKeyEncryptCipher.doFinal(secretKeyBytes);
            dataOutputStream.writeInt(encryptedSecretKeyBytes.length);
            dataOutputStream.write(encryptedSecretKeyBytes);
            dataOutputStream.flush();
            IvParameterSpec parameterSpec = new IvParameterSpec(secretKeyBytes);
            Cipher decryptCipher = Cipher.getInstance("AES/CFB8/NoPadding");
            Cipher encryptCipher = Cipher.getInstance("AES/CFB8/NoPadding");
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            CipherInputStream cipherInputStream = new CipherInputStream(bufferedInputStream, decryptCipher);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(bufferedOutputStream, encryptCipher);
            dataInputStream = new DataInputStream(cipherInputStream);
            dataOutputStream = new DataOutputStream(cipherOutputStream);
            dataOutputStream.writeInt(authenticationKey.length);
            dataOutputStream.write(authenticationKey);
            dataOutputStream.writeInt(syncObject.bytesPerAudioPacket);
            dataOutputStream.flush();
            while (running) {
                // Get a buffer of audio data
                dataInputStream.readFully(dataBuffer[bufferIndex]);
                connectionMade = true;

                boolean dataPassed =
                        syncObject.dataQueue.offer(dataBuffer[bufferIndex]);

                if (!dataPassed) {
                    // if current buffer not used to queue,
                    // will be used as next read buffer, should not update
                    // Filled up. Throw away everything that's in the network
                    // queue.
                    Log.w(TAG, "drop " + syncObject.bytesPerAudioPacket + " bytes");
                    continue;
                }
                bufferIndex = (bufferIndex + 1) % numBuffers;
            }
        } catch (Exception e) {
            Log.i(TAG, "runImpl:exception:" + e);

            // Attempt to release resources
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException iex) {
                    Log.i(TAG, "exception while closing socket:" + iex);
                }
            }
        }

        return connectionMade;
    }
}
