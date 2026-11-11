package top.ddupan.iam.login.authentication.infrastructure.ad;

import java.util.List;
import javax.naming.Name;
import lombok.Getter;
import org.springframework.ldap.odm.annotations.Attribute;
import org.springframework.ldap.odm.annotations.Entry;
import org.springframework.ldap.odm.annotations.Id;

/** Persistence representation, deliberately separate from the domain user. */
@Getter
@Entry(objectClasses = "user")
public final class AdUserEntry {
    @Id private Name dn;
    @Attribute(name = "objectGUID", type = Attribute.Type.BINARY) private byte[] objectGuid;
    @Attribute(name = "sAMAccountName") private String accountName;
    @Attribute(name = "displayName") private String displayName;
    @Attribute(name = "mail") private String email;
    @Attribute(name = "memberOf") private List<String> memberOf;
    @Attribute(name = "userAccountControl") private String accountControl;
    @Attribute(name = "pwdLastSet") private String passwordLastSet;
}
