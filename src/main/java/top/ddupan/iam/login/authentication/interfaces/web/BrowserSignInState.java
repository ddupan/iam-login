package top.ddupan.iam.login.authentication.interfaces.web;

import top.ddupan.iam.login.authentication.domain.LoginTransaction;

/** HTTP-session storage plus presentation feedback. Authentication rules live in the aggregate. */
final class BrowserSignInState {
    final LoginTransaction transaction;
    String username = "";
    String error = "";

    BrowserSignInState(LoginTransaction transaction) { this.transaction = transaction; }
}
