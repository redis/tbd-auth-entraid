package redis.clients.authentication.entraid;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class ServicePrincipalInfo {

    public enum ServicePrincipalAccess {
        WithSecret, WithCert,
    }

    private String clientId;
    private String secret;
    private PrivateKey key;
    private X509Certificate cert;
    private String authority;
    private ServicePrincipalAccess accessWith;

    public ServicePrincipalInfo(String clientId, String secret, String authority) {
        this.clientId = clientId;
        this.secret = secret;
        this.authority = authority;
        accessWith = ServicePrincipalAccess.WithSecret;
    }

    public ServicePrincipalInfo(String clientId, PrivateKey key, X509Certificate cert,
            String authority) {
        this.clientId = clientId;
        this.key = key;
        this.cert = cert;
        this.authority = authority;
        accessWith = ServicePrincipalAccess.WithCert;
    }

    public String getClientId() {
        return clientId;
    }

    public String getSecret() {
        return secret;
    }

    public PrivateKey getKey() {
        return key;
    }

    public X509Certificate getCert() {
        return cert;
    }

    public String getAuthority() {
        return authority;
    }

    public ServicePrincipalAccess getAccessWith() {
        return accessWith;
    }
}
