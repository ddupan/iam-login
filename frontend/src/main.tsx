import { createRoot } from "react-dom/client";
import "./i18n";
import { readPageContext } from "./page-context";
import { AccountPage } from "./pages/AccountPage";
import { AdminApp } from "./pages/AdminApp";
import { ConsentPage } from "./pages/ConsentPage";
import { DevicePage } from "./pages/DevicePage";
import { ErrorPage } from "./pages/ErrorPage";
import { SignInPage } from "./pages/SignInPage";
import { TotpSetupPage } from "./pages/TotpSetupPage";
import "./style.css";

const context = readPageContext();
createRoot(document.getElementById("root")!).render(
  context.step === "admin" ? <AdminApp context={context} />
    : context.step === "error" ? <ErrorPage context={context} />
    : context.step === "account" ? <AccountPage context={context} />
    : context.step === "totp-setup" ? <TotpSetupPage context={context} />
    : context.step === "consent" ? <ConsentPage context={context} />
      : context.step === "device" ? <DevicePage context={context} />
      : <SignInPage context={context} />,
);
