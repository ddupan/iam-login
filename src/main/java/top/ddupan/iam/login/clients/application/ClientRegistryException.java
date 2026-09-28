package top.ddupan.iam.login.clients.application;

public final class ClientRegistryException extends RuntimeException {
    public enum Kind { NOT_FOUND, CONFLICT, UNAVAILABLE }
    private final Kind kind;
    public ClientRegistryException(Kind kind) { super("Client registry " + kind); this.kind = kind; }
    public Kind kind() { return kind; }
}
