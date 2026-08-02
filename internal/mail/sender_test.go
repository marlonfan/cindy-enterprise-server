package mail

import (
	"strings"
	"testing"
	"time"
)

func TestNewSMTPSenderValidation(t *testing.T) {
	t.Parallel()
	for _, cfg := range []SMTPConfig{
		{},
		{Host: "mail.example.test", Port: 465},
		{Host: "mail.example.test", Port: 465, FromAddress: "invalid"},
		{Host: "mail.example.test", Port: 465, FromAddress: "sender@example.test", Username: "sender"},
		{Host: "mail.example.test", Port: 465, FromAddress: "sender@example.test", TLSMode: "plain"},
		{Host: "mail.example.test", Port: 465, FromAddress: "sender@example.test", FromName: "Cindy\r\nBcc: bad@example.test"},
	} {
		if _, err := NewSMTPSender(cfg); err == nil {
			t.Fatalf("expected validation error for %+v", cfg)
		}
	}
}

func TestSMTPSenderBuildMessage(t *testing.T) {
	t.Parallel()
	sender, err := NewSMTPSender(SMTPConfig{
		Host: "mail.example.test", Port: 465, FromAddress: "sender@example.test",
		FromName: "Cindy 企业服务", TLSMode: "tls", Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := sender.buildMessage("user@example.test", Email{
		Subject: "登录验证码", PlainText: "code 123456", HTML: "<strong>123456</strong>",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := string(message)
	for _, expected := range []string{
		"multipart/alternative", `text/plain; charset="utf-8"`, `text/html; charset="utf-8"`,
		"code 123456", "<strong>123456</strong>", "sender@example.test", "user@example.test",
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("message missing %q", expected)
		}
	}
	if !strings.Contains(raw, "=?utf-8?q?") && !strings.Contains(raw, "=?utf-8?b?") {
		t.Fatal("non-ASCII headers were not MIME encoded")
	}
}

func TestSMTPSenderBuildMessageRejectsHeaderInjection(t *testing.T) {
	t.Parallel()
	sender, err := NewSMTPSender(SMTPConfig{Host: "mail.example.test", Port: 587, FromAddress: "sender@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.buildMessage("user@example.test", Email{Subject: "ok\r\nBcc: attacker@example.test"}); err == nil {
		t.Fatal("expected subject header injection to be rejected")
	}
}
