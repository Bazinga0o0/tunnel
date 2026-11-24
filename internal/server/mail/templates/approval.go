package templates

import (
	"bytes"
	"fmt"
	htmltmpl "html/template"
	texttmpl "text/template"
)

const approvalNeededTextTmpl = `A new tunnel account waits for approval.

Account: {{.Email}}

The owner has verified the email address. Until an admin approves the account, it cannot create tokens or reservations or open tunnels.

Approve or reject it here:

{{.Link}}
`

const approvalNeededHTMLTmpl = `<!doctype html>
<html><body style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 32px 24px; color: #18181b;">
  <h1 style="font-size: 22px; margin: 0 0 16px;">An account waits for approval</h1>
  <p style="font-size: 15px; line-height: 1.6; margin: 0 0 16px;">
    Account: <strong>{{.Email}}</strong>
  </p>
  <p style="font-size: 15px; line-height: 1.6; margin: 0 0 24px;">
    The owner has verified the email address. Until an admin approves the account, it cannot create tokens or reservations or open tunnels.
  </p>
  <p style="margin: 0 0 24px;">
    <a href="{{.Link}}" style="display: inline-block; background: #18181b; color: #fff; text-decoration: none; padding: 10px 18px; border-radius: 6px; font-size: 14px;">Review approvals</a>
  </p>
  <p style="font-size: 13px; color: #71717a; line-height: 1.6; margin: 0;">
    Or paste this link into your browser:<br/>
    <a href="{{.Link}}" style="color: #71717a; word-break: break-all;">{{.Link}}</a>
  </p>
</body></html>
`

const accountApprovedTextTmpl = `Your tunnel account has been approved.

You can now create tokens and reservations and open tunnels. Log in here:

{{.Link}}
`

const accountApprovedHTMLTmpl = `<!doctype html>
<html><body style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 32px 24px; color: #18181b;">
  <h1 style="font-size: 22px; margin: 0 0 16px;">Your account has been approved</h1>
  <p style="font-size: 15px; line-height: 1.6; margin: 0 0 24px;">
    You can now create tokens and reservations and open tunnels.
  </p>
  <p style="margin: 0 0 24px;">
    <a href="{{.Link}}" style="display: inline-block; background: #18181b; color: #fff; text-decoration: none; padding: 10px 18px; border-radius: 6px; font-size: 14px;">Log in</a>
  </p>
  <p style="font-size: 13px; color: #71717a; line-height: 1.6; margin: 0;">
    Or paste this link into your browser:<br/>
    <a href="{{.Link}}" style="color: #71717a; word-break: break-all;">{{.Link}}</a>
  </p>
</body></html>
`

var (
	approvalNeededText  = texttmpl.Must(texttmpl.New("approval_needed.txt").Parse(approvalNeededTextTmpl))
	approvalNeededHTML  = htmltmpl.Must(htmltmpl.New("approval_needed.html").Parse(approvalNeededHTMLTmpl))
	accountApprovedText = texttmpl.Must(texttmpl.New("account_approved.txt").Parse(accountApprovedTextTmpl))
	accountApprovedHTML = htmltmpl.Must(htmltmpl.New("account_approved.html").Parse(accountApprovedHTMLTmpl))
)

// ApprovalNeeded returns rendered text and HTML bodies for the mail to the
// admins when the account with the address email starts to wait for
// approval. link is the admin page with the waiting accounts.
func ApprovalNeeded(email, link string) (text, html string, err error) {
	data := struct{ Email, Link string }{Email: email, Link: link}
	var tb, hb bytes.Buffer
	if err := approvalNeededText.Execute(&tb, data); err != nil {
		return "", "", fmt.Errorf("render approval-needed text: %w", err)
	}
	if err := approvalNeededHTML.Execute(&hb, data); err != nil {
		return "", "", fmt.Errorf("render approval-needed html: %w", err)
	}
	return tb.String(), hb.String(), nil
}

// AccountApprovedSubject is the subject of the AccountApproved mail; the
// admin panel and the admin CLI send it.
const AccountApprovedSubject = "Your tunnel account has been approved"

// AccountApproved returns rendered text and HTML bodies for the mail to the
// owner of an account an admin has approved. loginLink is the login page.
func AccountApproved(loginLink string) (text, html string, err error) {
	data := struct{ Link string }{Link: loginLink}
	var tb, hb bytes.Buffer
	if err := accountApprovedText.Execute(&tb, data); err != nil {
		return "", "", fmt.Errorf("render account-approved text: %w", err)
	}
	if err := accountApprovedHTML.Execute(&hb, data); err != nil {
		return "", "", fmt.Errorf("render account-approved html: %w", err)
	}
	return tb.String(), hb.String(), nil
}
