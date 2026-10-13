import { Trans, useTranslation } from "react-i18next";
import { Alert, Single, Steps } from "../components/Chrome";
import { Passkey } from "../components/Passkey";
import { SubmitForm } from "../components/SubmitForm";
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
      </Single>
    );
  }
  const who = context.identity.username;
  if (context.step === "mfa-pending") {
    return (
      <Single below={<><Restart context={context} label={t("signin.switchAccount")} /><span>{t("signin.lostFactor")}</span></>}>
        <Steps current={2} />
        {context.app && context.passkey === "authenticate" && <ContinueTo app={context.app} />}
        {context.passkey === "unavailable"
          ? <Alert>{t("signin.secondFactorUnavailable")}</Alert>
          : <Passkey csrf={context.csrf} initial={context.passkey} who={who} />}
      </Single>
    );
  }
  return (
    <Single>
      <div className="lead-block"><h1>{t("signin.signedIn")}</h1></div>
      <div className="who"><span className="avatar" aria-hidden="true">{who.slice(0, 1).toUpperCase()}</span>
        <div><span>{who}</span><span>{context.identity.email || t("common.noEmail")}</span></div></div>
      {context.identity.groups.length > 0 && (
        <div className="chips" aria-label={t("common.groups")}>{context.identity.groups.map(group => <span key={group} className="chip">{group}</span>)}</div>
      )}
      <SubmitForm action={context.action} csrf={context.csrf} label={t("common.signOut")} className="secondary" />
    </Single>
  );
}
