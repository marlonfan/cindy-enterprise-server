// Command preview-verification-email renders a static preview of the
// verification code email into a single self-contained .html file using a
// fixed sample code. It never sends mail and contains no credentials.
//
// Usage:
//
//	go run ./cmd/preview-verification-email [-out preview.html]
package main

import (
	"flag"
	"log"
	"os"

	"github.com/marlonfan/cindy-enterprise-server/internal/mail"
)

func main() {
	out := flag.String("out", "preview-verification-email.html", "output file path")
	flag.Parse()

	email, err := mail.RenderVerificationCode(mail.VerificationCodeParams{
		Code:            "483920",
		ValidityMinutes: 10,
		ProductName:     "Cindy Enterprise",
		SupportAddress:  "support@example.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, []byte(email.HTML), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("preview written to %s (subject: %s)", *out, email.Subject)
}
