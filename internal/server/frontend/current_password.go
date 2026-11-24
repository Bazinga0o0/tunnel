package frontend

import (
	"net/http"
	"time"
)

// passwordVerdict is the outcome of checkCurrentPassword.
type passwordVerdict int

const (
	// passwordCorrect: the password matches.
	passwordCorrect passwordVerdict = iota
	// passwordWrong: the password does not match; the attempt stays counted.
	passwordWrong
	// passwordLimited: a login limit refused the attempt before any hash.
	passwordLimited
	// passwordUndecided: the check failed (no free hash slot, a database
	// error); the error says why.
	passwordUndecided
)

// checkCurrentPassword checks password against the stored password of the
// signed-in account userID, whose stored address is email. The password
// change on the settings page and the admin's re-entry before promote,
// demote and password reset use it.
//
// The check counts against the two login limits of the web UI, before the
// password is hashed: the per-client limit (Options.LoginFailuresPerIP, the
// client's address) and the per-account limit (LoginFailuresPerAccount,
// keyed on the stored address, which is the key a login with that address
// uses). As at login, the attempt is counted up front, so that parallel
// attempts cannot pass a limit together; a correct password, and a check the
// server could not decide, gives the slots back, so that only wrong
// passwords stay counted. Over a limit the verdict is passwordLimited with
// the time after which a new attempt has room, and nothing is hashed.
//
// The caller answers each verdict; err is set for passwordUndecided only.
func (o Options) checkCurrentPassword(r *http.Request, userID int64, email, password string) (verdict passwordVerdict, retryAfter time.Duration, err error) {
	lim := o.limiters
	ipKey := sourceKey(clientIP(r))
	ipStamp, retry, ok := lim.loginIP.take(ipKey)
	if !ok {
		return passwordLimited, retry, nil
	}
	acctKey := o.keyOf(email)
	acctStamp, retry, ok := lim.loginAccount.take(acctKey)
	if !ok {
		lim.loginIP.giveBack(ipKey, ipStamp)
		return passwordLimited, retry, nil
	}
	giveBack := func() {
		lim.loginIP.giveBack(ipKey, ipStamp)
		lim.loginAccount.giveBack(acctKey, acctStamp)
	}

	match, err := o.Users.VerifyPassword(r.Context(), userID, password)
	switch {
	case err != nil:
		giveBack()
		return passwordUndecided, 0, err
	case !match:
		// The failure is final: it counts in the failure table's order
		// and credit only now (confirm).
		lim.loginAccount.confirm(acctKey, acctStamp)
		return passwordWrong, 0, nil
	}
	giveBack()
	return passwordCorrect, 0, nil
}
