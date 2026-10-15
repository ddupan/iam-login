import { useTranslation } from "react-i18next";
import type { CsrfToken } from "../page-context";
import { Alert } from "./Chrome";
import { SubmitForm } from "./SubmitForm";

/** The server sends a code; an unknown one reads as a wrong code. */
const ERRORS = { invalid: "totp.error.invalid", throttled: "signin.error.throttled" } as const;

/** A 6-digit authenticator app code, posted as a form: the server owns the factor. */
export function TotpCode({ action, csrf, error, label }: { action: string; csrf: CsrfToken; error: string; label: string }) {
  const { t } = useTranslation();
  const message = error && (ERRORS[error as keyof typeof ERRORS] ?? ERRORS.invalid);
  return <>
    {message && <Alert>{t(message)}</Alert>}
    <SubmitForm action={action} csrf={csrf} label={label}>
      <div className="field">
        <label htmlFor="code">{t("totp.code")}</label>
        <input id="code" name="code" className="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}"
          maxLength={6} required autoFocus placeholder={t("totp.codePlaceholder")} aria-invalid={message ? true : undefined} />
      </div>
    </SubmitForm>
  </>;
}
