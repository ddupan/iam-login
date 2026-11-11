package top.ddupan.iam.login.support;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import java.net.InetAddress;
import java.security.KeyStore;
import java.time.Instant;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Lazily initialized LDAPS fixture: loading test metadata must not start a server. */
public final class AdDirectoryFixture implements AutoCloseable {
    static final String BASE = "dc=example,dc=test";
    static final String USER_DN = "cn=Alice," + BASE;
    static final byte[] GUID = HexFormat.of().parseHex("33221100554477668899aabbccddeeff");
    static final String SERVICE_DN = "cn=svc," + BASE;
    /** The read-only service account, as spring.ldap.username/password. */
    public static final String SERVICE_USER = "svc@example.test", SERVICE_PASSWORD = "service-password";
    /** objectGUID of a disabled account (userAccountControl 514), as the UUID AD's byte order gives. */
    public static final String DISABLED_GUID = "0000000a-000b-000c-0d0e-0f1011121314";
    private final SSLContext original;
    private final InMemoryDirectoryServer ldap;
    public final AtomicInteger binds = new AtomicInteger();
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
                    } else if (name.equalsIgnoreCase("bob@example.test")) {
                        request.setRequest(new SimpleBindRequest("cn=Bob," + BASE, request.getRequest().getPassword().getValue()));
                    } else if (name.equalsIgnoreCase("svc@example.test")) {
                        request.setRequest(new SimpleBindRequest(SERVICE_DN, request.getRequest().getPassword().getValue()));
                    } else if (!name.equals(USER_DN) && !name.equals("cn=Bob," + BASE)) {
                        throw new LDAPException(ResultCode.INVALID_CREDENTIALS, "Invalid credentials");
                    }
                }
            });
            ldap = new InMemoryDirectoryServer(config);
            ldap.startListening();
            ldap.add(new Entry(BASE, new Attribute("objectClass", "domain"),
                new Attribute("dc", "example")));
            ldap.add(new Entry(USER_DN,
                new Attribute("objectClass", "user"),
                new Attribute("cn", "Alice"),
                new Attribute("sAMAccountName", "alice"),
                new Attribute("userPrincipalName", "alice@example.test"),
                new Attribute("userPassword", "fixture-password"),
                new Attribute("displayName", "Alice </script><script>attack()</script>"),
                new Attribute("mail", "alice@example.test"),
                new Attribute("objectGUID", GUID),
                // Three groups: stored as ImmutableCollections.ListN, the shape native serialization needs hints for.
                new Attribute("userAccountControl", "512"),
                new Attribute("memberOf", "CN=gitea-admins," + BASE, "CN=MixedCase," + BASE, "CN=staff," + BASE)));
            ldap.add(new Entry("cn=Bob," + BASE,
                new Attribute("objectClass", "user"),
                new Attribute("cn", "Bob"),
                new Attribute("sAMAccountName", "bob"),
                new Attribute("userPrincipalName", "bob@example.test"),
                new Attribute("userPassword", "fixture-password"),
                new Attribute("displayName", "Bob"),
                new Attribute("userAccountControl", "512"),
                new Attribute("objectGUID", new byte[16])));
            ldap.add(new Entry("cn=Carol," + BASE,
                new Attribute("objectClass", "user"),
                new Attribute("sAMAccountName", "carol"),
                new Attribute("userAccountControl", "514"),
                new Attribute("objectGUID", HexFormat.of().parseHex("0a0000000b000c000d0e0f1011121314"))));
            ldap.add(new Entry(SERVICE_DN,
                new Attribute("objectClass", "user"),
                new Attribute("sAMAccountName", "svc"),
                new Attribute("userAccountControl", "66048"),
                new Attribute("userPassword", SERVICE_PASSWORD),
                new Attribute("objectGUID", HexFormat.of().parseHex("ffffffffffffffffffffffffffffffff"))));
        } catch (Exception ex) { throw new ExceptionInInitializerError(ex); }
    }


    public String url() { return "ldaps://localhost:" + ldap.getListenPort(); }
    /** Sets alice's pwdLastSet (a FILETIME), as AD does when the password changes. */
    public void passwordChanged(Instant at) {
        long filetime = (at.getEpochSecond() * 10_000_000L + at.getNano() / 100) + 116_444_736_000_000_000L;
        try {
            ldap.modify(USER_DN, new Modification(ModificationType.REPLACE, "pwdLastSet", Long.toString(filetime)));
        } catch (LDAPException ex) { throw new IllegalStateException(ex); }
    }
    public String mismatchedHostnameUrl() { return "ldaps://127.0.0.1:" + ldap.getListenPort(); }
    @Override public void close() { ldap.shutDown(true); SSLContext.setDefault(original); }
}
