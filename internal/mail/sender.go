package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"net"
	netmail "net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

type VerificationSender interface {
	SendVerificationCode(context.Context, string, Email) error
}

type SMTPConfig struct {
	Host        string
	Port        int
	Username    string
	Password    string
	FromAddress string
	FromName    string
	TLSMode     string
	ServerName  string
	Timeout     time.Duration
}

type SMTPSender struct {
	cfg SMTPConfig
}

func NewSMTPSender(cfg SMTPConfig) (*SMTPSender, error) {
	cfg.Host = strings.TrimSpace(cfg.Host)
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.FromAddress = strings.TrimSpace(cfg.FromAddress)
	cfg.FromName = strings.TrimSpace(cfg.FromName)
	cfg.TLSMode = strings.ToLower(strings.TrimSpace(cfg.TLSMode))
	cfg.ServerName = strings.TrimSpace(cfg.ServerName)
	if cfg.Host == "" || cfg.Port < 1 || cfg.Port > 65535 {
		return nil, errors.New("SMTP host and valid port are required")
	}
	if cfg.FromAddress == "" {
		return nil, errors.New("SMTP from address is required")
	}
	from, err := netmail.ParseAddress(cfg.FromAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid SMTP from address: %w", err)
	}
	if from.Address == "" {
		return nil, errors.New("invalid SMTP from address")
	}
	cfg.FromAddress = from.Address
	if strings.ContainsAny(cfg.FromName, "\r\n") {
		return nil, errors.New("SMTP from name contains control characters")
	}
	if (cfg.Username == "") != (cfg.Password == "") {
		return nil, errors.New("SMTP username and password must be configured together")
	}
	if cfg.TLSMode == "" {
		cfg.TLSMode = "auto"
	}
	if cfg.TLSMode != "auto" && cfg.TLSMode != "tls" && cfg.TLSMode != "starttls" {
		return nil, errors.New("SMTP TLS mode must be auto, tls, or starttls")
	}
	if cfg.ServerName == "" {
		cfg.ServerName = cfg.Host
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &SMTPSender{cfg: cfg}, nil
}

func (s *SMTPSender) SendVerificationCode(ctx context.Context, recipient string, email Email) error {
	message, err := s.buildMessage(recipient, email)
	if err != nil {
		return err
	}
	client, err := s.dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	if s.cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.ServerName)); err != nil {
			return fmt.Errorf("authenticate SMTP connection: %w", err)
		}
	}
	if err := client.Mail(s.cfg.FromAddress); err != nil {
		return fmt.Errorf("set SMTP sender: %w", err)
	}
	parsedRecipient, _ := netmail.ParseAddress(recipient)
	if err := client.Rcpt(parsedRecipient.Address); err != nil {
		return fmt.Errorf("set SMTP recipient: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("start SMTP message: %w", err)
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write SMTP message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish SMTP message: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("close SMTP connection: %w", err)
	}
	return nil
}

func (s *SMTPSender) dial(ctx context.Context) (*smtp.Client, error) {
	address := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	dialer := &net.Dialer{Timeout: s.cfg.Timeout}
	deadline := time.Now().Add(s.cfg.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	tlsConfig := &tls.Config{ServerName: s.cfg.ServerName, MinVersion: tls.VersionTLS12}
	mode := s.cfg.TLSMode
	if mode == "auto" {
		if s.cfg.Port == 465 {
			mode = "tls"
		} else {
			mode = "starttls"
		}
	}

	if mode == "tls" {
		connection, err := (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, fmt.Errorf("connect SMTP TLS: %w", err)
		}
		_ = connection.SetDeadline(deadline)
		client, err := smtp.NewClient(connection, s.cfg.ServerName)
		if err != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("initialize SMTP TLS client: %w", err)
		}
		return client, nil
	}

	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect SMTP STARTTLS: %w", err)
	}
	_ = connection.SetDeadline(deadline)
	client, err := smtp.NewClient(connection, s.cfg.ServerName)
	if err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("initialize SMTP client: %w", err)
	}
	if supported, _ := client.Extension("STARTTLS"); !supported {
		_ = client.Close()
		return nil, errors.New("SMTP server does not advertise STARTTLS")
	}
	if err := client.StartTLS(tlsConfig); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("start SMTP TLS: %w", err)
	}
	return client, nil
}

func (s *SMTPSender) buildMessage(recipient string, email Email) ([]byte, error) {
	to, err := netmail.ParseAddress(strings.TrimSpace(recipient))
	if err != nil || to.Address == "" {
		return nil, errors.New("valid recipient address is required")
	}
	if strings.ContainsAny(email.Subject, "\r\n") {
		return nil, errors.New("email subject contains control characters")
	}

	var alternatives bytes.Buffer
	multipartWriter := multipart.NewWriter(&alternatives)
	plainHeaders := textproto.MIMEHeader{
		"Content-Type":              {`text/plain; charset="utf-8"`},
		"Content-Transfer-Encoding": {"8bit"},
	}
	plainWriter, err := multipartWriter.CreatePart(plainHeaders)
	if err != nil {
		return nil, fmt.Errorf("create plain email part: %w", err)
	}
	if _, err := plainWriter.Write([]byte(email.PlainText)); err != nil {
		return nil, fmt.Errorf("write plain email part: %w", err)
	}
	htmlHeaders := textproto.MIMEHeader{
		"Content-Type":              {`text/html; charset="utf-8"`},
		"Content-Transfer-Encoding": {"8bit"},
	}
	htmlWriter, err := multipartWriter.CreatePart(htmlHeaders)
	if err != nil {
		return nil, fmt.Errorf("create HTML email part: %w", err)
	}
	if _, err := htmlWriter.Write([]byte(email.HTML)); err != nil {
		return nil, fmt.Errorf("write HTML email part: %w", err)
	}
	if err := multipartWriter.Close(); err != nil {
		return nil, fmt.Errorf("finish multipart email: %w", err)
	}

	from := (&netmail.Address{Name: s.cfg.FromName, Address: s.cfg.FromAddress}).String()
	headers := []string{
		"From: " + from,
		"To: " + to.String(),
		"Subject: " + mime.QEncoding.Encode("utf-8", email.Subject),
		"Date: " + time.Now().Format(time.RFC1123Z),
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="` + multipartWriter.Boundary() + `"`,
	}
	return append([]byte(strings.Join(headers, "\r\n")+"\r\n\r\n"), alternatives.Bytes()...), nil
}
