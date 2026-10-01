import { createRoot } from "react-dom/client";
import { readPageContext } from "./page-context";
import { AdminApp } from "./pages/AdminApp";
import { SignInPage } from "./pages/SignInPage";
import "./style.css";

const context = readPageContext();
createRoot(document.getElementById("root")!).render(
  context.step === "admin" ? <AdminApp context={context} /> : <SignInPage context={context} />,
);
