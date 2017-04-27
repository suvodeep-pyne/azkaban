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

package azkaban.storage;

import azkaban.spi.Storage;
import azkaban.spi.StorageMetadata;
import com.google.inject.Inject;
import com.google.inject.name.Named;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;

import static azkaban.Constants.ConfigurationKeys.*;


public class HdfsStorage implements Storage {
  private final URI rootUri;
  private final FileSystem fs;

  @Inject
  public HdfsStorage(FileSystem fs, @Named(AZKABAN_STORAGE_HDFS_ROOT_URI) URI rootUri) {
    this.rootUri = rootUri;
    this.fs = fs;
  }

  @Override
  public InputStream get(URI key) throws IOException {
    return fs.open(new Path(key));
  }

  @Override
  public URI put(StorageMetadata metadata, File localFile) {
    throw new UnsupportedOperationException("Method not implemented");
  }

  @Override
  public boolean delete(URI key) {
    throw new UnsupportedOperationException("Method not implemented");
  }
}
