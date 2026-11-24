// Package templates renders email bodies (text + HTML) for transactional
// emails. No Tailwind — email clients need inline styles.
package templates

import (
	"bytes"
	"fmt"
	htmltmpl "html/template"
	texttmpl "text/template"
)

const verifyEmailTextTmpl = `Welcome to tunnel!

Please verify your email address by clicking the link below. The link expires in 24 hours.

{{.Link}}

If you didn't sign up, you can ignore this message.
`

const verifyEmailHTMLTmpl = `<!doctype html>
<html><body style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 32px 24px; color: #18181b;">
  <h1 style="font-size: 22px; margin: 0 0 16px;">Welcome to tunnel</h1>
  <p style="font-size: 15px; line-height: 1.6; margin: 0 0 24px;">
    Please verify your email address. The link expires in 24 hours.
  </p>
  <p style="margin: 0 0 24px;">
    <a href="{{.Link}}" style="display: inline-block; background: #18181b; color: #fff; text-decoration: none; padding: 10px 18px; border-radius: 6px; font-size: 14px;">Verify email</a>
  </p>
  <p style="font-size: 13px; color: #71717a; line-height: 1.6; margin: 0;">
    Or paste this link into your browser:<br/>
    <a href="{{.Link}}" style="color: #71717a; word-break: break-all;">{{.Link}}</a>
  </p>
  <p style="font-size: 12px; color: #a1a1aa; margin: 32px 0 0;">If you didn't sign up, you can ignore this message.</p>
</body></html>
`

var (
	verifyText = texttmpl.Must(texttmpl.New("verify.txt").Parse(verifyEmailTextTmpl))
	verifyHTML = htmltmpl.Must(htmltmpl.New("verify.html").Parse(verifyEmailHTMLTmpl))
)

// VerifyEmail returns rendered text and HTML bodies for the verification email.
func VerifyEmail(link string) (text, html string, err error) {
	data := struct{ Link string }{Link: link}
	var tb, hb bytes.Buffer
	if err := verifyText.Execute(&tb, data); err != nil {
		return "", "", fmt.Errorf("render verify text: %w", err)
	}
	if err := verifyHTML.Execute(&hb, data); err != nil {
		return "", "", fmt.Errorf("render verify html: %w", err)
	}
	return tb.String(), hb.String(), nil
}
