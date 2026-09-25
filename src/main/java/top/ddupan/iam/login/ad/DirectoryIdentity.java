package top.ddupan.iam.login.ad;

import java.util.List;

/** Directory key only: deliberately not a Hydra subject or a completed authentication. */
public record DirectoryIdentity(String objectGuid, String username, String displayName,
        String email, List<String> groups, List<String> groupDns) {
    public DirectoryIdentity {
        groups = List.copyOf(groups);
        groupDns = List.copyOf(groupDns);
    }
}
