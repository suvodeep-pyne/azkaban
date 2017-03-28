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

package azkaban.execapp;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import groovy.grape.Grape;
import groovy.lang.GroovyClassLoader;
import java.io.File;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.apache.log4j.Logger;

import static com.google.common.base.Preconditions.*;
import static java.util.Objects.*;


/**
 * This class resolves and downloads artifacts for the project using Grape
 *
 * By default, grape runs with the following defaults:
 * https://github.com/apache/groovy/blob/master/src/resources/groovy/grape/defaultGrapeConfig.xml
 *
 * To override default grape config
 * Configurations are read from system properties. @see groovy.grape.GrapeIvy
 *
 */
public class ArtifactResolver {
  private static final Logger log = Logger.getLogger(ArtifactResolver.class);

  public static void configureGrape(File grapeConfigFile) {
    System.setProperty("grape.config", requireNonNull(grapeConfigFile).getAbsolutePath());
  }

  /**
   * Parses the input artifact and downloads the
   * specified artifact possibly along with its transitive
   * dependencies and returns those as a set of local
   * uris
   *
   * @param uri  Artifact string artifactUri
   * @return List of resolved dependencies
   * @throws IllegalArgumentException If the artifact is not a valid URI
   */
  public List<URI> fetchDependency(URI uri) {
    return grab(parseUri(uri));
  }

  private Map<String, Object> parseUri(URI uri) {
    final String authority = requireNonNull(uri.getAuthority(), "URI is null");

    final String[] authorityTokens = authority.split(":");
    checkArgument(authorityTokens.length == 3,
        "Invalid artifactUri: Expected 'ivy://org:module:version', found " + authority);

    final Map<String, Object> artifactMap = Maps.newHashMap();
    artifactMap.put("org", authorityTokens[0]);
    artifactMap.put("module", authorityTokens[1]);
    artifactMap.put("version", authorityTokens[2]);

    return artifactMap;
  }

  /**
   * @param artifact to resolve
   * @return List of URIs of downloaded dependencies
   */
  private List<URI> grab(Map<String, Object> artifact) {
    // Set transitive to false by default
    if (!artifact.containsKey("transitive")) {
      artifact.put("transitive", false);
    }

    log.info("Resolving artifact: " + artifact);
    final Map<String, Object> args = ImmutableMap.<String, Object>builder()
        .put("classLoader", new GroovyClassLoader())
        .build();
    final URI[] uris = Grape.resolve(args, artifact);

    log.info("Resolved artifact(s): " + Arrays.toString(uris));
    return Lists.newArrayList(uris);
  }
}
