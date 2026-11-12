import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { Alert, Single, Steps } from "../components/Chrome";
import { Passkey, PasskeySignIn, usePasskeyAutofill, type Problem } from "../components/Passkey";
import { SubmitForm } from "../components/SubmitForm";
import { TotpCode } from "../components/TotpCode";
import type { SignInContext } from "../page-context";

/** Leave this sign-in (POST /signin/restart) and start over with another account. */
function Restart({ context, label }: { context: SignInContext; label: string }) {
  return <SubmitForm action="/signin/restart" csrf={context.csrf} label={label} className="link" />;
}

/** The server sends a code; an unknown one reads as a failed sign-in rather than leaking through. */
const ERRORS = { invalid: "signin.error.invalid", unavailable: "signin.error.unavailable", throttled: "signin.error.throttled" } as const;

function ErrorAlert({ code }: { code: string }) {
  const { t } = useTranslation();
  if (!code) return null;
  const error = ERRORS[code as keyof typeof ERRORS] ?? ERRORS.invalid;
  return <Alert kind={error === ERRORS.unavailable ? "warn" : "error"}>{t(error)}</Alert>;
}

function ContinueTo({ app }: { app: string }) {
  return <p className="lead"><Trans i18nKey="common.continueTo" values={{ app }} components={{ strong: <strong /> }} /></p>;
}

/** First screen: the name only. A passkey picked from the field's suggestions (autofill) signs in right away. */
function Identify({ context }: { context: SignInContext }) {
  const { t } = useTranslation();
  const [autofill, setAutofill] = useState<Problem | null>(null);
  const stopAutofill = usePasskeyAutofill(context.csrf, setAutofill);
  return (
    <Single below={<span>{t("signin.forgotPassword")}</span>}>
      <div className="lead-block">
        <h1>{t("signin.heading")}</h1>
        {context.app && <ContinueTo app={context.app} />}
      </div>
      <ErrorAlert code={context.error} />
      {autofill && <Alert>{t(`passkey.error.${autofill}`)}</Alert>}
      <SubmitForm action={context.action} csrf={context.csrf} label={t("common.continue")}>
        <div className="field">
          <label htmlFor="username">{t("signin.username")}</label>
          {/* "webauthn" is the WebAuthn Level 3 token that lets the browser offer passkeys here; the rule predates it. */}
          {/* oxlint-disable-next-line jsx-a11y/autocomplete-valid */}
          <input id="username" name="username" autoComplete="username webauthn" autoFocus required maxLength={256}
            defaultValue={context.name} />
        </div>
      </SubmitForm>
      <PasskeySignIn csrf={context.csrf} label={t("signin.usePasskey")} before={stopAutofill} />
    </Single>
  );
}

/** Second screen: the named account's passkey, or its password. */
function SignInAs({ context }: { context: SignInContext }) {
  const { t } = useTranslation();
  const who = context.name;
  const passkey = context.step === "passkey";
  return (
    <Single below={<><Restart context={context} label={t("signin.switchAccount")} /><span>{t("signin.forgotPassword")}</span></>}>
      <div className="lead-block">
        <h1>{t(passkey ? "signin.passkeyHeading" : "signin.passwordHeading")}</h1>
        {context.app && <ContinueTo app={context.app} />}
      </div>
      <div className="who"><span className="avatar" aria-hidden="true">{who.slice(0, 1).toUpperCase()}</span>
        <div><span>{who}</span></div></div>
      <ErrorAlert code={context.error} />
      {passkey ? <>
        <p className="lead">{t("passkey.verifyLead")}</p>
        <PasskeySignIn csrf={context.csrf} label={t("signin.usePasskey")} />
        <a className="switch" href="/signin?method=password">{t("signin.usePassword")}</a>
      </> : (
        <SubmitForm action={context.action} csrf={context.csrf} label={t("common.continue")}>
          {/* The name travels with the password, and tells password managers which account this is. */}
          <input name="username" value={who} autoComplete="username" readOnly hidden />
          <div className="field">
            <label htmlFor="password">{t("signin.password")}</label>
            <input id="password" name="password" type="password" autoComplete="current-password" autoFocus required
              maxLength={1024} aria-invalid={context.error ? true : undefined} />
          </div>
        </SubmitForm>
      )}
    </Single>
  );
}

export function SignInPage({ context }: { context: SignInContext }) {
  const { t } = useTranslation();
  if (context.step !== "mfa-pending") {
    return context.step === "identify" ? <Identify context={context} /> : <SignInAs context={context} />;
  }
  const who = context.identity.username;
  const { factor } = context;
  return (
    <Single below={<><Restart context={context} label={t("signin.switchAccount")} /><span>{t("signin.lostFactor")}</span></>}>
      <Steps current={2} />
      {context.app && (factor === "passkey" || factor === "totp") && <ContinueTo app={context.app} />}
      {factor === "unavailable" ? <Alert>{t("signin.secondFactorUnavailable")}</Alert>
        : factor === "totp" ? <>
          <div className="lead-block">
            <h1>{t("totp.verifyHeading")}</h1>
            <p className="lead">{t("totp.verifyLead")}</p>
          </div>
          <TotpCode action="/signin/totp" csrf={context.csrf} error={context.error} label={t("totp.verify")} />
          {context.other && <a className="switch" href="/signin/mfa?method=passkey">{t("totp.usePasskey")}</a>}
        </>
        : <Passkey csrf={context.csrf} initial={factor === "choose" ? "register" : "authenticate"} who={who}
          alternative={factor === "choose" ? <>
            <a className="secondary" href="/signin/totp/setup">{t("totp.choose")}</a>
            <p className="fine">{t("totp.chooseHint")}</p>
          </> : context.other && <a className="switch" href="/signin/mfa?method=totp">{t("passkey.useTotp")}</a>} />}
    </Single>
  );
}
