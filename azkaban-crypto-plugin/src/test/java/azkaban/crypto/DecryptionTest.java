/*
 * Copyright (C) 2016 LinkedIn Corp. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
 */
package azkaban.crypto;

import junit.framework.Assert;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Test;

import java.io.IOException;

public class DecryptionTest {

  @Test
  public void testV1_1() throws IOException {
    BasicConfigurator.configure();
    Logger.getRootLogger().setLevel(Level.DEBUG);

    String expected = "test";

    String ciphered = "eyJ2ZXIiOiIxLjEiLCJ2YWwiOiJpaE9CM2VzTzBad2F4cHZBV2Z5YUVicHZLQzJBWDJZZnVzS3hVWFN2R3A0PSJ9";
    String passphrase = "test1234";

    Crypto crypto = new Crypto();
    String actual = crypto.decrypt(ciphered, passphrase);
    Assert.assertEquals(expected, actual);

    try {
      new CryptoV1().decrypt(ciphered, passphrase);
      Assert.fail("Should have failed when decrypt v1.1 ciphered text with v1 decryption.");
    } catch (Exception e) {
      Assert.assertTrue(e instanceof RuntimeException);
    }
  }

  @Test
  public void testV1() throws IOException {
    BasicConfigurator.configure();
    Logger.getRootLogger().setLevel(Level.DEBUG);

    String expected = "test";

    String ciphered = "eyJ2ZXIiOiIxLjAiLCJ2YWwiOiJOd1hRejdOMjBXUU05SXEzaE94RVZnPT0ifQ==";
    String passphrase = "test1234";

    Crypto crypto = new Crypto();
    String actual = crypto.decrypt(ciphered, passphrase);
    Assert.assertEquals(expected, actual);

    try {
      new CryptoV1_1().decrypt(ciphered, passphrase);
      Assert.fail("Should have failed when decrypt v1 ciphered text with v1.1 decryption.");
    } catch (Exception e) {
      Assert.assertTrue(e instanceof RuntimeException);
    }
  }

  @Test
  public void testInvalidParams() throws IOException {
    BasicConfigurator.configure();
    Logger.getRootLogger().setLevel(Level.DEBUG);

    String expected = "test";
    String[] cipheredtexts = {"eyJ2ZXIiOiIxLjAiLCJ2YWwiOiJOd1hRejdOMjBXUU05SXEzaE94RVZnPT0ifQ==", null, ""};
    String[] passphrases = {"test1234", null, ""};

    for (String cipheredtext : cipheredtexts) {
      for (String passphrase : passphrases) {
        Crypto crypto = new Crypto();
        if(!StringUtils.isEmpty(cipheredtext) && !StringUtils.isEmpty(passphrase)) {
          String actual = crypto.decrypt(cipheredtext, passphrase);
          Assert.assertEquals(expected, actual);
        } else {
          try {
            crypto.decrypt(cipheredtext, passphrase);
            Assert.fail("Encyption should have failed with invalid parameters. cipheredtext: "
                        + cipheredtext + " , passphrase: " + passphrase);
          } catch (Exception e) {
            Assert.assertTrue(e instanceof IllegalArgumentException);
          }
        }
      }
    }
  }
}