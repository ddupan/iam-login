package top.ddupan.iam.login.clients.domain;

public final class ClientRepositoryException extends RuntimeException {
    public enum Kind { NOT_FOUND, CONFLICT, UNAVAILABLE }
    private final Kind kind;
    public ClientRepositoryException(Kind kind) { super("Client repository " + kind); this.kind = kind; }
    public Kind kind() { return kind; }
}
