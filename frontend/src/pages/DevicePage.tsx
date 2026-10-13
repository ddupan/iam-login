import { useTranslation } from "react-i18next";
import { Alert, Brand, Single } from "../components/Chrome";
import type { DeviceContext } from "../page-context";

/** The device grant's verification page: the code a device shows, then the outcome. */
export function DevicePage({ context }: { context: DeviceContext }) {
  const { t } = useTranslation();
  const { device } = context;
  const top = <div className="brand-row"><Brand host={false} /><span className="lead">{device.username}</span></div>;
  if (device.result === "done" || device.result === "denied") {
    return (
      <Single top={top}>
        <div className="lead-block">
          <h1>{device.result === "done" ? t("device.done") : t("device.denied")}</h1>
          <p className="lead">{device.result === "done" ? t("device.doneLead") : t("device.deniedLead")}</p>
        </div>
      </Single>
    );
  }
  return (
    <Single top={top}>
      <div className="lead-block"><h1>{t("device.heading")}</h1></div>
      {device.result === "invalid" && <Alert>{t("device.invalid")}</Alert>}
      {/* GET: the framework's verification endpoint takes the code as a query parameter, without CSRF. */}
      <form method="get" action={context.action}>
        <div className="field">
          <label htmlFor="user_code">{t("device.code")}</label>
          <input id="user_code" name="user_code" required autoFocus autoComplete="off" spellCheck={false}
            maxLength={20} className="mono" defaultValue={device.userCode}
            aria-invalid={device.result === "invalid" ? true : undefined} />
        </div>
        <button className="primary" type="submit">{t("common.continue")}</button>
      </form>
    </Single>
  );
}
