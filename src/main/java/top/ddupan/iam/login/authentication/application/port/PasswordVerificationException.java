package top.ddupan.iam.login.authentication.application.port;

/** Adapter failures translated into application vocabulary, without vendor exception details. */
public final class PasswordVerificationException extends RuntimeException {
    public enum Reason { REJECTED, DISABLED, LOCKED, PASSWORD_EXPIRED, ACCOUNT_EXPIRED, UNAVAILABLE }
    private final Reason reason;

    public PasswordVerificationException(Reason reason) {
        super(reason.name());
        this.reason = reason;
    }

    public Reason reason() { return reason; }
}
