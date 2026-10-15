import { QRCodeSVG } from "qrcode.react";
import { useTranslation } from "react-i18next";
import { Single } from "../components/Chrome";
import { TotpCode } from "../components/TotpCode";
import type { TotpSetupContext } from "../page-context";

/** Scan (or type) the key, then confirm it with a code; the key is only saved once a code matches. */
export function TotpSetupPage({ context }: { context: TotpSetupContext }) {
  const { t } = useTranslation();
  const { totp } = context;
  return (
    <Single wide below={<><a href={context.back}>{t("totp.back")}</a><span>{t("totp.help")}</span></>}>
      <div className="lead-block">
        <h1>{t("totp.setupHeading")}</h1>
        <p className="lead">{t("totp.setupLead")}</p>
      </div>
      <div className="totp-key">
        <QRCodeSVG value={totp.uri} size={152} marginSize={0} className="qr" title={t("totp.qr")} />
        <div className="lead-block">
          <span className="hint">{t("totp.manual")}</span>
          <code className="secret">{totp.secret.match(/.{1,4}/g)?.join(" ")}</code>
          <span className="fine">{t("totp.account", { account: totp.account, issuer: totp.issuer })}</span>
        </div>
      </div>
      <TotpCode action={context.action} csrf={context.csrf} error={context.error} label={t("totp.enable")} />
    </Single>
  );
}
