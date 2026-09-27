package top.ddupan.iam.login.support;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import java.net.InetAddress;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
/** Lazily initialized LDAPS fixture: loading test metadata must not start a server. */
public final class AdDirectoryFixture implements AutoCloseable {
    static final String BASE = "dc=example,dc=test";
    static final String USER_DN = "cn=Alice," + BASE;
    static final byte[] GUID = java.util.HexFormat.of().parseHex("33221100554477668899aabbccddeeff");
    private final SSLContext original;
    private final InMemoryDirectoryServer ldap;
    public final java.util.concurrent.atomic.AtomicInteger binds = new java.util.concurrent.atomic.AtomicInteger();
    public volatile long bindConnection;
    public volatile long searchConnection;
    public AdDirectoryFixture() {
        try {
            original = SSLContext.getDefault();
            var store = KeyStore.getInstance("PKCS12");
            try (var stream = AdDirectoryFixture.class.getResourceAsStream("/ldap/fixture.p12")) {
                store.load(stream, "fixture-only".toCharArray());
            }
            var keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(store, "fixture-only".toCharArray());
            var trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(store);
            var ssl = SSLContext.getInstance("TLS");
            ssl.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
            SSLContext.setDefault(ssl);
            var config = new InMemoryDirectoryServerConfig(BASE);
            config.setSchema(null);
            config.setListenerConfigs(InMemoryListenerConfig.createLDAPSConfig("ldaps",
                InetAddress.getByName("127.0.0.1"), 0, ssl.getServerSocketFactory(), ssl.getSocketFactory()));
            config.addInMemoryOperationInterceptor(new InMemoryOperationInterceptor() {
                @Override
                public void processSearchResult(InMemoryInterceptedSearchResult result) {
                    searchConnection = result.getConnectionID();
                    try {
                        // Like Samba AD's DomainDnsZones/ForestDnsZones continuation references.
                        // A client following this reference would fail instead of returning the user.
                        result.sendSearchReference(new SearchResultReference(
                            new String[]{"ldap://127.0.0.1:1/DC=other,DC=test"}, null));
                    } catch (LDAPException ex) { throw new IllegalStateException(ex); }
                }

                @Override
                public void processSimpleBindRequest(InMemoryInterceptedSimpleBindRequest request) throws LDAPException {
                    binds.incrementAndGet();
                    bindConnection = request.getConnectionID();
                    String name = request.getRequest().getBindDN();
                    String subcode = switch (name) {
                        case "disabled@example.test" -> "533";
                        case "locked@example.test" -> "775";
                        case "expired@example.test" -> "532";
                        default -> null;
                    };
                    if (subcode != null) throw new LDAPException(ResultCode.INVALID_CREDENTIALS,
                        "80090308: LdapErr: DSID-0C090334, comment: AcceptSecurityContext error, data " + subcode + ", v1db1");
                    if (name.equalsIgnoreCase("alice@example.test")) {
                        request.setRequest(new SimpleBindRequest(USER_DN, request.getRequest().getPassword().getValue()));
                    } else if (!name.equals(USER_DN)) {
                        throw new LDAPException(ResultCode.INVALID_CREDENTIALS, "Invalid credentials");
                    }
                }
            });
            ldap = new InMemoryDirectoryServer(config);
            ldap.startListening();
            ldap.add(new Entry(BASE, new com.unboundid.ldap.sdk.Attribute("objectClass", "domain"),
                new com.unboundid.ldap.sdk.Attribute("dc", "example")));
            ldap.add(new Entry(USER_DN,
                new com.unboundid.ldap.sdk.Attribute("objectClass", "user"),
                new com.unboundid.ldap.sdk.Attribute("cn", "Alice"),
                new com.unboundid.ldap.sdk.Attribute("sAMAccountName", "alice"),
                new com.unboundid.ldap.sdk.Attribute("userPrincipalName", "alice@example.test"),
                new com.unboundid.ldap.sdk.Attribute("userPassword", "fixture-password"),
                new com.unboundid.ldap.sdk.Attribute("displayName", "Alice </script><script>attack()</script>"),
                new com.unboundid.ldap.sdk.Attribute("mail", "alice@example.test"),
                new com.unboundid.ldap.sdk.Attribute("objectGUID", GUID),
                new com.unboundid.ldap.sdk.Attribute("memberOf", "CN=gitea-admins," + BASE, "CN=MixedCase," + BASE)));
        } catch (Exception ex) { throw new ExceptionInInitializerError(ex); }
    }


    public String url() { return "ldaps://localhost:" + ldap.getListenPort(); }
    public String mismatchedHostnameUrl() { return "ldaps://127.0.0.1:" + ldap.getListenPort(); }
    @Override public void close() { ldap.shutDown(true); SSLContext.setDefault(original); }
}
