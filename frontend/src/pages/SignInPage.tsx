import { Trans, useTranslation } from "react-i18next";
import { Alert, Single, Steps } from "../components/Chrome";
import { Passkey, PasskeySignIn } from "../components/Passkey";
import { SubmitForm } from "../components/SubmitForm";
import { TotpCode } from "../components/TotpCode";
import type { SignInContext } from "../page-context";

/** Leave this sign-in (POST /signin/restart) and start over with another account. */
function Restart({ context, label }: { context: SignInContext; label: string }) {
  return <SubmitForm action={context.action} csrf={context.csrf} label={label} className="link" />;
}

/** The server sends a code; an unknown one reads as a failed sign-in rather than leaking through. */
const ERRORS = { invalid: "signin.error.invalid", unavailable: "signin.error.unavailable", throttled: "signin.error.throttled" } as const;

function ContinueTo({ app }: { app: string }) {
  return <p className="lead"><Trans i18nKey="common.continueTo" values={{ app }} components={{ strong: <strong /> }} /></p>;
}

export function SignInPage({ context }: { context: SignInContext }) {
  const { t } = useTranslation();
  if (context.step === "password") {
    const error = context.error && (ERRORS[context.error as keyof typeof ERRORS] ?? ERRORS.invalid);
    return (
      <Single below={<span>{t("signin.forgotPassword")}</span>}>
        <div className="lead-block">
          <h1>{t("signin.heading")}</h1>
          {context.app && <ContinueTo app={context.app} />}
        </div>
        {error && <Alert kind={error === ERRORS.unavailable ? "warn" : "error"}>{t(error)}</Alert>}
        <SubmitForm action={context.action} csrf={context.csrf} label={t("common.continue")}>
          <div className="field">
            <label htmlFor="username">{t("signin.username")}</label>
            <input id="username" name="username" autoComplete="username" autoFocus required maxLength={256}
              defaultValue={context.name} aria-invalid={error ? true : undefined} />
          </div>
          <div className="field">
            <label htmlFor="password">{t("signin.password")}</label>
            <input id="password" name="password" type="password" autoComplete="current-password" required
              maxLength={1024} aria-invalid={error ? true : undefined} />
          </div>
        </SubmitForm>
        <PasskeySignIn csrf={context.csrf} />
      </Single>
    );
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
