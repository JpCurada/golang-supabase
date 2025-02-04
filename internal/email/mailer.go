// internal/email/mailer.go
package email

import (
    "bytes"
    "fmt"
    "html/template"
    "net/smtp"

    "github.com/JpCurada/golang-supabase/internal/config"
)

type Mailer struct {
    config config.SMTPConfig
    auth   smtp.Auth
}

func NewMailer(config config.SMTPConfig) *Mailer {
    auth := smtp.PlainAuth("", config.Username, config.Password, config.Host)
    return &Mailer{
        config: config,
        auth:   auth,
    }
}

func (m *Mailer) SendVerificationEmail(to, name, token string) error {
    subject := "Verify Your Email"
    verificationLink := fmt.Sprintf("http://localhost:8080/verify-email?token=%s", token)

    templateData := struct {
        Name string
        Link string
    }{
        Name: name,
        Link: verificationLink,
    }

    body := new(bytes.Buffer)
    tmpl := template.Must(template.New("verification").Parse(`
        <html>
        <body>
            <h2>Hello {{.Name}},</h2>
            <p>Please verify your email address by clicking the link below:</p>
            <p><a href="{{.Link}}">Verify Email</a></p>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't register for an account, please ignore this email.</p>
        </body>
        </html>
    `))

    if err := tmpl.Execute(body, templateData); err != nil {
        return err
    }

    mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
    msg := fmt.Sprintf("Subject: %s\n%s\n%s", subject, mime, body.String())

    addr := fmt.Sprintf("%s:%s", m.config.Host, m.config.Port)
    return smtp.SendMail(
        addr,
        m.auth,
        m.config.From,
        []string{to},
        []byte(msg),
    )
}

func (m *Mailer) SendPasswordResetEmail(to, name, token string) error {
    subject := "Reset Your Password"
    resetLink := fmt.Sprintf("http://localhost:8080/reset-password?token=%s", token)

    templateData := struct {
        Name string
        Link string
    }{
        Name: name,
        Link: resetLink,
    }

    body := new(bytes.Buffer)
    tmpl := template.Must(template.New("reset").Parse(`
        <html>
        <body>
            <h2>Hello {{.Name}},</h2>
            <p>We received a request to reset your password. Click the link below to reset it:</p>
            <p><a href="{{.Link}}">Reset Password</a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request a password reset, please ignore this email.</p>
        </body>
        </html>
    `))

    if err := tmpl.Execute(body, templateData); err != nil {
        return err
    }

    mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
    msg := fmt.Sprintf("Subject: %s\n%s\n%s", subject, mime, body.String())

    addr := fmt.Sprintf("%s:%s", m.config.Host, m.config.Port)
    return smtp.SendMail(
        addr,
        m.auth,
        m.config.From,
        []string{to},
        []byte(msg),
    )
}