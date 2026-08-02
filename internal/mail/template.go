package mail

import (
	_ "embed"
	"fmt"
	"html/template"
	"strings"
	"unicode"
)

//go:embed template.html
var htmlSource string

// VerificationCodeParams describes the data rendered into the verification
// code email. ProductName and SupportAddress are optional; the verification
// code and validity period are required and validated.
type VerificationCodeParams struct {
	// Code is the six-digit verification code. Must contain exactly six
	// ASCII digits; anything else is rejected with an error.
	Code string

	// ValidityMinutes is how long the code stays valid. Values <= 0 fall
	// back to 10 minutes.
	ValidityMinutes int

	// ProductName is shown in the header and footer. Defaults to
	// "Cindy Enterprise". Control characters are stripped to keep header
	// and subject values safe.
	ProductName string

	// SupportAddress is an optional email address ("support@example.com")
	// or http(s) URL shown in the footer. When it looks like an http(s)
	// URL it is linked as-is; otherwise it is linked as a mailto address.
	SupportAddress string
}

// Email is a complete, render-ready message. Callers are responsible for
// SMTP transport, MIME header encoding of non-ASCII senders, and must never
// log Code, To, or other personal data.
type Email struct {
	Subject   string
	HTML      string
	PlainText string
}

const (
	defaultProductName  = "Cindy Enterprise"
	defaultValidityMin  = 10
	maxProductNameChars = 40
)

var htmlTemplate = template.Must(template.New("verification-code-html").Funcs(template.FuncMap{
	"formatCode": formatCode,
}).Parse(htmlSource))

var plainTemplate = template.Must(template.New("verification-code-plain").Parse(plainSource))

// RenderVerificationCode renders the HTML and plain-text versions of the
// Cindy Enterprise verification code email.
func RenderVerificationCode(params VerificationCodeParams) (Email, error) {
	code, err := normalizeCode(params.Code)
	if err != nil {
		return Email{}, err
	}
	validity := params.ValidityMinutes
	if validity <= 0 {
		validity = defaultValidityMin
	}
	if validity > 1440 {
		validity = 1440
	}
	productName := sanitizeProductName(params.ProductName)
	supportAddress := strings.TrimSpace(params.SupportAddress)

	data := struct {
		ProductName     string
		Code            string
		ValidityMinutes int
		SupportAddress  string
		SupportHref     string
		HasSupport      bool
		Preheader       string
	}{
		ProductName:     productName,
		Code:            code,
		ValidityMinutes: validity,
		SupportAddress:  supportAddress,
		SupportHref:     supportHref(supportAddress),
		HasSupport:      supportAddress != "",
		Preheader:       productName + " 登录验证码：有效期 " + fmt.Sprintf("%d", validity) + " 分钟。",
	}

	var html strings.Builder
	if err := htmlTemplate.Execute(&html, data); err != nil {
		return Email{}, fmt.Errorf("render html template: %w", err)
	}
	var plain strings.Builder
	if err := plainTemplate.Execute(&plain, data); err != nil {
		return Email{}, fmt.Errorf("render plain text template: %w", err)
	}

	return Email{
		Subject:   productName + " 登录验证码",
		HTML:      html.String(),
		PlainText: plain.String(),
	}, nil
}

// normalizeCode trims the code and requires exactly six ASCII digits.
func normalizeCode(code string) (string, error) {
	trimmed := strings.TrimSpace(code)
	if len(trimmed) != 6 {
		return "", fmt.Errorf("verification code must be exactly 6 digits, got %d characters", len(trimmed))
	}
	for _, r := range trimmed {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("verification code must contain digits only")
		}
	}
	return trimmed, nil
}

// sanitizeProductName strips control characters (CR/LF in particular so the
// value can never be used to inject extra headers) and collapses whitespace.
func sanitizeProductName(name string) string {
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.TrimSpace(name))
	if name == "" {
		return defaultProductName
	}
	fields := strings.Fields(name)
	if len(fields) == 0 {
		return defaultProductName
	}
	joined := strings.Join(fields, " ")
	if len([]rune(joined)) > maxProductNameChars {
		joined = string([]rune(joined)[:maxProductNameChars])
	}
	return joined
}

// supportHref decides whether SupportAddress is linked directly (http/https)
// or treated as an email address. Plain mailto: values are never linked, so
// a raw address is always safe to interpolate as text.
func supportHref(address string) string {
	if address == "" {
		return ""
	}
	lower := strings.ToLower(address)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return address
	}
	return "mailto:" + address
}

// formatCode inserts HTML comments between digits so email clients render
// the code as six separate non-collapsible characters instead of one long
// unbreakable run.
func formatCode(code string) template.HTML {
	var b strings.Builder
	for i, r := range code {
		if i > 0 {
			b.WriteString("<!-- -->")
		}
		b.WriteRune(r)
	}
	return template.HTML(b.String())
}

const plainSource = `{{.ProductName}} 登录验证码

你正在登录 {{.ProductName}}。请输入以下验证码完成验证：

{{.Code}}

验证码有效期 {{.ValidityMinutes}} 分钟。

安全提醒：如果这不是你本人操作，请忽略此邮件，并考虑修改账号密码。
验证码仅用于 {{.ProductName}} 登录，请勿泄露给他人。

{{if .HasSupport}}如需帮助，请联系 {{.SupportAddress}}。
{{end}}此邮件由 {{.ProductName}} 自动发送，请勿直接回复。`
