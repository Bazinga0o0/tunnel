package templates

import (
	"bytes"
	"fmt"
	htmltmpl "html/template"
	texttmpl "text/template"
)

const resetTextTmpl = `Someone requested a password reset for your tunnel account.

If that was you, use the link below. It expires in 1 hour.

{{.Link}}

If it wasn't you, you can safely ignore this message.
`

const resetHTMLTmpl = `<!doctype html>
<html><body style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 32px 24px; color: #18181b;">
  <h1 style="font-size: 22px; margin: 0 0 16px;">Reset your password</h1>
  <p style="font-size: 15px; line-height: 1.6; margin: 0 0 24px;">
    Someone requested a password reset for your tunnel account. If that was you, click the link below. It expires in 1 hour.
  </p>
  <p style="margin: 0 0 24px;">
    <a href="{{.Link}}" style="display: inline-block; background: #18181b; color: #fff; text-decoration: none; padding: 10px 18px; border-radius: 6px; font-size: 14px;">Reset password</a>
  </p>
  <p style="font-size: 13px; color: #71717a; line-height: 1.6; margin: 0;">
    Or paste this link into your browser:<br/>
    <a href="{{.Link}}" style="color: #71717a; word-break: break-all;">{{.Link}}</a>
  </p>
  <p style="font-size: 12px; color: #a1a1aa; margin: 32px 0 0;">If you didn't request a reset, you can safely ignore this message.</p>
</body></html>
`

var (
	resetText = texttmpl.Must(texttmpl.New("reset.txt").Parse(resetTextTmpl))
	resetHTML = htmltmpl.Must(htmltmpl.New("reset.html").Parse(resetHTMLTmpl))
)

// PasswordReset returns rendered text and HTML bodies for the reset email.
func PasswordReset(link string) (text, html string, err error) {
	data := struct{ Link string }{Link: link}
	var tb, hb bytes.Buffer
	if err := resetText.Execute(&tb, data); err != nil {
		return "", "", fmt.Errorf("render reset text: %w", err)
	}
	if err := resetHTML.Execute(&hb, data); err != nil {
		return "", "", fmt.Errorf("render reset html: %w", err)
	}
	return tb.String(), hb.String(), nil
}
