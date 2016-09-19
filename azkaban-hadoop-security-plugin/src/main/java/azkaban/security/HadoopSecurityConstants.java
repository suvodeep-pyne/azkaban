package azkaban.security;

import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.server.jobtracker.JTConfig;

/**
 * Created by spyne on 9/19/16.
 */
public class HadoopSecurityConstants {

    /** The Kerberos principal for the job tracker. */
    public static final String JT_PRINCIPAL = JTConfig.JT_USER_NAME;
    /** The Kerberos principal for the resource manager. */
    public static final String RM_PRINCIPAL = "yarn.resourcemanager.principal";
    public static final String HADOOP_JOB_TRACKER = "mapred.job.tracker";
    public static final String HADOOP_JOB_TRACKER_2 =
        "mapreduce.jobtracker.address";
    public static final String HADOOP_YARN_RM = "yarn.resourcemanager.address";
    /**
     * the key that will be used to set proper signature for each of the hcat
     * token when multiple hcat tokens are required to be fetched.
     * */
    public static final String HIVE_TOKEN_SIGNATURE_KEY =
        "hive.metastore.token.signature";
    public static final Text DEFAULT_RENEWER = new Text("azkaban mr tokens");
    static final String FS_HDFS_IMPL_DISABLE_CACHE =
        "fs.hdfs.impl.disable.cache";
    static final String OTHER_NAMENODES_TO_GET_TOKEN = "other_namenodes";
    /**
     * the settings to be defined by user indicating if there are hcat locations
     * other than the default one the system should pre-fetch hcat token from.
     * Note: Multiple thrift uris are supported, use comma to separate the values,
     * values are case insensitive.
     * */
    static final String EXTRA_HCAT_LOCATION = "other_hcat_location";
    static final String AZKABAN_KEYTAB_LOCATION = "proxy.keytab.location";
    static final String AZKABAN_PRINCIPAL = "proxy.user";
    static final String OBTAIN_JOBHISTORYSERVER_TOKEN =
        "obtain.jobhistoryserver.token";
}
