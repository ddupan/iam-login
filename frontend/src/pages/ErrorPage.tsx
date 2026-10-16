import { useTranslation } from "react-i18next";
import { Single } from "../components/Chrome";
import type { ErrorContext } from "../page-context";

/** What went wrong, by status only; the way on is always the account page. */
export function ErrorPage({ context }: { context: ErrorContext }) {
  const { t } = useTranslation();
  const kind = context.status === 403 ? "403" as const : context.status === 404 ? "404" as const
    : context.status >= 500 ? "server" as const : "request" as const;
  return (
    <Single>
      <div className="lead-block">
        <h1>{t(`error.${kind}.heading`)}</h1>
        <p className="lead">{t(`error.${kind}.lead`)}</p>
      </div>
      <a className="primary" href="/account">{t("error.account")}</a>
    </Single>
  );
}
