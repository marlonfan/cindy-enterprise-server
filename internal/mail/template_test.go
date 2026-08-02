package mail

import (
	"strings"
	"testing"
)

func TestRenderVerificationCodeBasic(t *testing.T) {
	t.Parallel()
	email, err := RenderVerificationCode(VerificationCodeParams{
		Code:            "483920",
		ValidityMinutes: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if email.Subject != "Cindy Enterprise 登录验证码" {
		t.Fatalf("unexpected subject: %q", email.Subject)
	}
	htmlNoComments := strings.ReplaceAll(email.HTML, "<!-- -->", "")
	if !strings.Contains(htmlNoComments, "483920") {
		t.Fatal("html is missing the verification code")
	}
	if !strings.Contains(email.PlainText, "483920") {
		t.Fatal("plain text is missing the verification code")
	}
	if !strings.Contains(email.HTML, "验证码有效期 10 分钟") {
		t.Fatal("html is missing the validity period")
	}
	if !strings.Contains(email.PlainText, "验证码有效期 10 分钟") {
		t.Fatal("plain text is missing the validity period")
	}
	// Code must appear exactly once in plain text (no accidental duplication).
	if count := strings.Count(email.PlainText, "483920"); count != 1 {
		t.Fatalf("plain text contains code %d times, want 1", count)
	}
}

func TestRenderVerificationCodeCustomValues(t *testing.T) {
	t.Parallel()
	email, err := RenderVerificationCode(VerificationCodeParams{
		Code:            "123456",
		ValidityMinutes: 30,
		ProductName:     "Acme 内网",
		SupportAddress:  "support@acme.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(email.Subject, "Acme 内网") {
		t.Fatalf("subject missing custom product name: %q", email.Subject)
	}
	if !strings.Contains(email.HTML, "Acme 内网") {
		t.Fatal("html missing custom product name")
	}
	if !strings.Contains(email.HTML, "support@acme.test") {
		t.Fatal("html missing support address")
	}
	if !strings.Contains(email.HTML, "mailto:support@acme.test") {
		t.Fatal("support address should be linked as mailto")
	}
	if !strings.Contains(email.HTML, "验证码有效期 30 分钟") {
		t.Fatal("custom validity not rendered")
	}
	if !strings.Contains(email.PlainText, "support@acme.test") {
		t.Fatal("plain text missing support address")
	}
}

func TestRenderVerificationCodeDefaults(t *testing.T) {
	t.Parallel()
	email, err := RenderVerificationCode(VerificationCodeParams{Code: "000001"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(email.HTML, "验证码有效期 10 分钟") {
		t.Fatal("default validity of 10 minutes not applied")
	}
	if !strings.Contains(email.HTML, "Cindy Enterprise") {
		t.Fatal("default product name not applied")
	}
}

func TestRenderVerificationCodeInvalid(t *testing.T) {
	t.Parallel()
	for _, code := range []string{"", "12345", "1234567", "abcdef", "12345a", "12 3456", "１２３４５６"} {
		if _, err := RenderVerificationCode(VerificationCodeParams{Code: code}); err == nil {
			t.Fatalf("expected error for code %q", code)
		}
	}
}

func TestRenderVerificationCodeEscapesHTML(t *testing.T) {
	t.Parallel()
	email, err := RenderVerificationCode(VerificationCodeParams{
		Code:            "123456",
		ValidityMinutes: 10,
		ProductName:     `<script>alert("xss")</script>`,
		SupportAddress:  `"><img src=x onerror=alert(1)>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	html := email.HTML
	if strings.Contains(html, "<script>") {
		t.Fatal("product name was not escaped in html")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatal("product name should be HTML-escaped")
	}
	if strings.Contains(html, "<img src=x") {
		t.Fatal("support address was not escaped in html")
	}
	if strings.Contains(email.Subject, "\n") || strings.Contains(email.Subject, "\r") {
		t.Fatal("subject contains control characters")
	}
}

func TestRenderVerificationCodeSanitizesProductName(t *testing.T) {
	t.Parallel()
	email, err := RenderVerificationCode(VerificationCodeParams{
		Code:        "123456",
		ProductName: "Cindy Enterprise\r\nBcc: attacker@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(email.Subject, "\r") || strings.Contains(email.Subject, "\n") {
		t.Fatal("subject allows header injection via product name")
	}
	if !strings.Contains(email.Subject, "Cindy Enterprise") {
		t.Fatal("sanitized product name missing from subject")
	}
}

func TestRenderVerificationCodeAccessibilityContent(t *testing.T) {
	t.Parallel()
	email, err := RenderVerificationCode(VerificationCodeParams{
		Code:            "987654",
		ValidityMinutes: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	html := email.HTML
	if !strings.Contains(html, `lang="zh-CN"`) {
		t.Fatal("html is missing lang attribute")
	}
	if !strings.Contains(html, "非本人操作") && !strings.Contains(html, "不是") {
		t.Fatal("html is missing the not-you instruction")
	}
	if !strings.Contains(html, "color-scheme") {
		t.Fatal("html is missing color-scheme meta for dark mode")
	}
	if !strings.Contains(email.PlainText, "不是") {
		t.Fatal("plain text is missing the not-you instruction")
	}
}

func TestRenderVerificationCodeFormatting(t *testing.T) {
	t.Parallel()
	email, err := RenderVerificationCode(VerificationCodeParams{Code: "135790", ValidityMinutes: 10})
	if err != nil {
		t.Fatal(err)
	}
	// The six digits must render as separate non-collapsible characters.
	if !strings.Contains(email.HTML, "1<!-- -->3") {
		t.Fatal("digits are not separated by non-collapsible separators")
	}
	if !strings.Contains(email.HTML, "role=\"presentation\"") {
		t.Fatal("tables should be marked role=presentation for accessibility")
	}
}
