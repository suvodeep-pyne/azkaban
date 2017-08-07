/*
 * Copyright 2017 LinkedIn Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package azkaban.client;

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Objects.requireNonNull;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.codehaus.jackson.JsonFactory;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HeadlessClient {

  private static final Logger log = LoggerFactory.getLogger(HeadlessClient.class);
  private static final JsonFactory factory = new JsonFactory();

  private final String user;
  private final File privateKeyFile;

  public HeadlessClient(final String user, final String privateKeyFilePath) {
    this.user = requireNonNull(user, "Username is null!");

    this.privateKeyFile = new File(
        requireNonNull(privateKeyFilePath, "Private Key filepath is null!"));
    checkArgument(this.privateKeyFile.exists(), "Private Key file doesn't exist!");

  }

  private static String decodeChallengeMessage(final File privateKeyFile, final String base64String)
      throws Exception {
    log.info("Decoding challenge message with private key");
    final BufferedInputStream in = new BufferedInputStream(new FileInputStream(privateKeyFile));
    final byte[] sshPrivateKey = IOUtils.toByteArray(in);

    final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(sshPrivateKey);

    final KeyFactory kf = KeyFactory.getInstance("RSA");
    final PrivateKey privateKey = kf.generatePrivate(keySpec);
    final Cipher decryptCipher = Cipher.getInstance("RSA");
    decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

    final byte[] rawBytes = Base64.decodeBase64(base64String.getBytes("US-ASCII"));
    log.debug("Encrypted size: " + rawBytes.length);
    final byte[] decodedBytes = decryptCipher.doFinal(rawBytes);
    log.debug("Decoded size: " + decodedBytes.length);
    final String decodedString = new String(decodedBytes, "US-ASCII");
    log.debug("Decoded String: " + decodedString);
    return decodedString;
  }

  public void login(final URL azkabanUrl) {

  }

  public String getChallenge(final String azkabanUrl)
      throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
    final String challengeUrl = azkabanUrl + "/restli/liuser?action=headlessChallenge";
    final String data = "{\"username\": \"" + this.user + "\"}";

    final HttpPost httpPost = new HttpPost(challengeUrl);
    final HttpEntity entity = new StringEntity(data, ContentType.APPLICATION_JSON);
    httpPost.setEntity(entity);

    final HttpClient httpclient = createHttpClient();

    final ResponseHandler<String> responseHandler = new BasicResponseHandler();
    final String response = httpclient.execute(httpPost, responseHandler);

    final JsonParser parser = factory.createJsonParser(response);
    final ObjectMapper mapper = new ObjectMapper();
    final JsonNode node = mapper.readTree(parser);

    final String base64Result = node.get("value").getTextValue();
    return base64Result;
  }

  private HttpClient createHttpClient()
      throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
    final SSLContext sslContext = new SSLContextBuilder()
        .loadTrustMaterial(null, (cert, authType) -> true)
        .build();
    final SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext,
        new NoopHostnameVerifier());

    return HttpClientBuilder.create()
        .setSSLSocketFactory(socketFactory)
        .build();
  }

}
