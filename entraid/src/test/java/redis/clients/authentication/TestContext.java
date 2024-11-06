package redis.clients.authentication;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Properties;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import redis.clients.jedis.HostAndPort;
import redis.clients.jedis.Protocol;

public class TestContext {

    private static final String localContext = "./src/test/resources/local.context";
    private String clientId;
    private String authority;
    private String clientSecret;
    private PrivateKey privateKey;
    private X509Certificate cert;
    private Set<String> redisScopes;

    public static final TestContext DEFAULT = new TestContext();

    private TestContext() {
        if (Files.exists(Paths.get(localContext))) {
            try {
                Properties properties = new Properties();
                properties.load(Files.newBufferedReader(Paths.get(localContext)));
                this.clientId = properties.getProperty("CLIENT_ID");
                this.authority = properties.getProperty("AUTHORITY");
                this.clientSecret = properties.getProperty("CLIENT_SECRET");
                this.privateKey = getPrivateKey(properties.getProperty("PRIVATE_KEY"));
                this.cert = getCert(properties.getProperty("CERT"));
                String redisScopesProp = properties.getProperty("REDIS_SCOPES");
                if (redisScopesProp != null && !redisScopesProp.isEmpty()) {
                    this.redisScopes = new HashSet<>(Arrays.asList(redisScopesProp.split(";")));
                }
            } catch (IOException e) {
                throw new RuntimeException("Failed to load local.context", e);
            }
        } else {
            this.clientId = System.getenv("CLIENT_ID");
            this.authority = System.getenv("AUTHORITY");
            this.clientSecret = System.getenv("CLIENT_SECRET");
            String redisScopesEnv = System.getenv("REDIS_SCOPES");
            if (redisScopesEnv != null && !redisScopesEnv.isEmpty()) {
                this.redisScopes = new HashSet<>(Arrays.asList(redisScopesEnv.split(";")));
            }
        }
    }

    public TestContext(String clientId, String authority, String clientSecret,
            Set<String> redisScopes) {
        this.clientId = clientId;
        this.authority = authority;
        this.clientSecret = clientSecret;
        this.redisScopes = redisScopes;
    }

    public String getClientId() {
        return clientId;
    }

    public String getAuthority() {
        return authority;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public X509Certificate getCert() {
        return cert;
    }

    public Set<String> getRedisScopes() {
        return redisScopes;
    }

    private static HashMap<String, EndpointConfig> endpointConfigs;

    private static List<HostAndPort> sentinelHostAndPortList = new ArrayList<>();
    private static List<HostAndPort> clusterHostAndPortList = new ArrayList<>();
    private static List<HostAndPort> stableClusterHostAndPortList = new ArrayList<>();

    static {
        String endpointsPath = System.getenv().getOrDefault("REDIS_ENDPOINTS_CONFIG_PATH",
                "src/test/resources/endpoints.json");
        try {
            endpointConfigs = EndpointConfig.loadFromJSON(endpointsPath);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        sentinelHostAndPortList.add(new HostAndPort("localhost", Protocol.DEFAULT_SENTINEL_PORT));
        sentinelHostAndPortList
                .add(new HostAndPort("localhost", Protocol.DEFAULT_SENTINEL_PORT + 1));
        sentinelHostAndPortList
                .add(new HostAndPort("localhost", Protocol.DEFAULT_SENTINEL_PORT + 2));
        sentinelHostAndPortList
                .add(new HostAndPort("localhost", Protocol.DEFAULT_SENTINEL_PORT + 3));
        sentinelHostAndPortList
                .add(new HostAndPort("localhost", Protocol.DEFAULT_SENTINEL_PORT + 4));

        clusterHostAndPortList.add(new HostAndPort("localhost", 7379));
        clusterHostAndPortList.add(new HostAndPort("localhost", 7380));
        clusterHostAndPortList.add(new HostAndPort("localhost", 7381));
        clusterHostAndPortList.add(new HostAndPort("localhost", 7382));
        clusterHostAndPortList.add(new HostAndPort("localhost", 7383));
        clusterHostAndPortList.add(new HostAndPort("localhost", 7384));

        stableClusterHostAndPortList.add(new HostAndPort("localhost", 7479));
        stableClusterHostAndPortList.add(new HostAndPort("localhost", 7480));
        stableClusterHostAndPortList.add(new HostAndPort("localhost", 7481));
    }

    public static EndpointConfig getRedisEndpoint(String endpointName) {
        if (!endpointConfigs.containsKey(endpointName)) {
            throw new IllegalArgumentException("Unknown Redis endpoint: " + endpointName);
        }

        return endpointConfigs.get(endpointName);
    }

    public static List<HostAndPort> getSentinelServers() {
        return sentinelHostAndPortList;
    }

    public static List<HostAndPort> getClusterServers() {
        return clusterHostAndPortList;
    }

    public static List<HostAndPort> getStableClusterServers() {
        return stableClusterHostAndPortList;
    }

    private static PrivateKey getPrivateKey(String privateKey) {
        try {
            // Decode the base64 encoded key into a byte array
            byte[] decodedKey = Base64.getDecoder().decode(privateKey);

            // Generate the private key from the decoded byte array using PKCS8EncodedKeySpec
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Use the correct algorithm (e.g., "RSA", "EC", "DSA")
            PrivateKey key = keyFactory.generatePrivate(keySpec);
            return key;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private static X509Certificate getCert(String cert) {
        try {
            // Convert the Base64 encoded string into a byte array
            byte[] encoded = java.util.Base64.getDecoder().decode(cert);

            // Create a CertificateFactory for X.509 certificates
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            // Generate the certificate from the byte array
            X509Certificate certificate = (X509Certificate) certificateFactory
                    .generateCertificate(new ByteArrayInputStream(encoded));
            return certificate;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
