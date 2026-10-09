import { createRoot } from "react-dom/client";
import { readPageContext } from "./page-context";
import { AdminApp } from "./pages/AdminApp";
import { ConsentPage } from "./pages/ConsentPage";
import { DevicePage } from "./pages/DevicePage";
import { SignInPage } from "./pages/SignInPage";
import "./style.css";

const context = readPageContext();
createRoot(document.getElementById("root")!).render(
  context.step === "admin" ? <AdminApp context={context} />
    : context.step === "consent" ? <ConsentPage context={context} />
      : context.step === "device" ? <DevicePage context={context} />
      : <SignInPage context={context} />,
);
