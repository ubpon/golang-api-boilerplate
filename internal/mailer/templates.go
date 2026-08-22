package mailer

import (
	"bytes"
	"fmt"
	"html/template"
	"net/url"
	"strings"
	textTemplate "text/template"
)

const (
	TemplateVerifyEmail    = "verify_email"
	TemplatePasswordReset  = "password_reset"
	TemplatePasswordChange = "password_changed"
)

type templatePair struct {
	subject string
	text    *textTemplate.Template
	html    *template.Template
}

type templateData struct {
	Name       string
	ActionURL  string
	ExpiresIn  string
	AppName    string
	SupportURL string
}

var templates = map[string]templatePair{
	TemplateVerifyEmail: {
		subject: "Confirm your email address",
		text: textTemplate.Must(textTemplate.New("verify_text").Parse(
			"Hi{{if .Name}} {{.Name}}{{end}},\n\n" +
				"Confirm your email address for {{.AppName}} by opening the link below.\n\n" +
				"{{.ActionURL}}\n\n" +
				"The link expires in {{.ExpiresIn}}. If you did not create this account you can ignore this message.\n")),
		html: template.Must(template.New("verify_html").Parse(
			`<p>Hi{{if .Name}} {{.Name}}{{end}},</p>` +
				`<p>Confirm your email address for {{.AppName}}:</p>` +
				`<p><a href="{{.ActionURL}}">Confirm email address</a></p>` +
				`<p>The link expires in {{.ExpiresIn}}. If you did not create this account you can ignore this message.</p>`)),
	},
	TemplatePasswordReset: {
		subject: "Reset your password",
		text: textTemplate.Must(textTemplate.New("reset_text").Parse(
			"Hi{{if .Name}} {{.Name}}{{end}},\n\n" +
				"Someone asked to reset the {{.AppName}} password for this address.\n\n" +
				"{{.ActionURL}}\n\n" +
				"The link expires in {{.ExpiresIn}} and can be used once. If this was not you, no action is needed.\n")),
		html: template.Must(template.New("reset_html").Parse(
			`<p>Hi{{if .Name}} {{.Name}}{{end}},</p>` +
				`<p>Someone asked to reset the {{.AppName}} password for this address.</p>` +
				`<p><a href="{{.ActionURL}}">Reset password</a></p>` +
				`<p>The link expires in {{.ExpiresIn}} and can be used once. If this was not you, no action is needed.</p>`)),
	},
	TemplatePasswordChange: {
		subject: "Your password was changed",
		text: textTemplate.Must(textTemplate.New("changed_text").Parse(
			"Hi{{if .Name}} {{.Name}}{{end}},\n\n" +
				"The password on your {{.AppName}} account was just changed and all other sessions were signed out.\n\n" +
				"If this was not you, reset your password immediately at {{.SupportURL}}.\n")),
		html: template.Must(template.New("changed_html").Parse(
			`<p>Hi{{if .Name}} {{.Name}}{{end}},</p>` +
				`<p>The password on your {{.AppName}} account was just changed and all other sessions were signed out.</p>` +
				`<p>If this was not you, <a href="{{.SupportURL}}">reset your password</a> immediately.</p>`)),
	},
}

type Composer struct {
	appName string
	baseURL string
}

func NewComposer(appName, baseURL string) *Composer {
	return &Composer{appName: appName, baseURL: strings.TrimRight(baseURL, "/")}
}

func (c *Composer) VerifyEmail(to, name, token, expiresIn string) (Message, error) {
	return c.compose(TemplateVerifyEmail, to, templateData{
		Name:      name,
		ActionURL: c.link("/verify-email", token),
		ExpiresIn: expiresIn,
	})
}

func (c *Composer) PasswordReset(to, name, token, expiresIn string) (Message, error) {
	return c.compose(TemplatePasswordReset, to, templateData{
		Name:      name,
		ActionURL: c.link("/reset-password", token),
		ExpiresIn: expiresIn,
	})
}

func (c *Composer) PasswordChanged(to, name string) (Message, error) {
	return c.compose(TemplatePasswordChange, to, templateData{
		Name:       name,
		SupportURL: c.baseURL + "/forgot-password",
	})
}

func (c *Composer) link(path, token string) string {
	return fmt.Sprintf("%s%s?token=%s", c.baseURL, path, url.QueryEscape(token))
}

func (c *Composer) compose(name, to string, data templateData) (Message, error) {
	tpl, ok := templates[name]
	if !ok {
		return Message{}, fmt.Errorf("mailer: unknown template %q", name)
	}
	data.AppName = c.appName
	if data.SupportURL == "" {
		data.SupportURL = c.baseURL
	}

	var text, html bytes.Buffer
	if err := tpl.text.Execute(&text, data); err != nil {
		return Message{}, fmt.Errorf("mailer: render %s text: %w", name, err)
	}
	if err := tpl.html.Execute(&html, data); err != nil {
		return Message{}, fmt.Errorf("mailer: render %s html: %w", name, err)
	}

	return Message{
		To:       to,
		Subject:  tpl.subject,
		TextBody: text.String(),
		HTMLBody: html.String(),
		Template: name,
	}, nil
}
