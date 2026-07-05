package tui

import (
	"encoding/json"
	"fmt"
	"time"
)

// PasswordHistoryEntry holds a previously used password with a timestamp.
type PasswordHistoryEntry struct {
	Password string    `json:"password"`
	LastUsed time.Time `json:"last_used"`
}

// LoginPayload stores credential data.
// TOTP key is stored inline — like Bitwarden/Vaultwarden — so one item
// covers both the password and the 2FA code.
// History keeps the last 10 passwords with timestamps.
type LoginPayload struct {
	Name     string                 `json:"name"`
	Username string                 `json:"username"`
	Password string                 `json:"password"`
	URL      string                 `json:"url,omitempty"`
	TOTPKey  string                 `json:"totp_key,omitempty"` // base32 TOTP secret
	Notes    string                 `json:"notes,omitempty"`
	History  []PasswordHistoryEntry `json:"history,omitempty"`
}

// CardPayload stores bank card data.
type CardPayload struct {
	Name           string `json:"name"`
	CardholderName string `json:"cardholder_name"`
	Number         string `json:"number"`
	ExpMonth       string `json:"exp_month"`
	ExpYear        string `json:"exp_year"`
	CVV            string `json:"cvv"`
	Notes          string `json:"notes,omitempty"`
}

// NotePayload stores a secure note.
type NotePayload struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// IdentityPayload stores personal identity information.
type IdentityPayload struct {
	Name      string `json:"name"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	Company   string `json:"company,omitempty"`
	Address   string `json:"address,omitempty"`
	Notes     string `json:"notes,omitempty"`
}

// AuthPayload stores a standalone TOTP authenticator entry.
type AuthPayload struct {
	Name   string `json:"name"`
	Secret string `json:"secret"` // base32
	Issuer string `json:"issuer,omitempty"`
	Label  string `json:"label,omitempty"`
}

// parseLoginPayload handles both the old {"login":...} format and the new
// {"username":...} format, so existing vault items open correctly.
func parseLoginPayload(raw []byte, meta string) LoginPayload {
	var p LoginPayload
	_ = json.Unmarshal(raw, &p)
	if p.Name == "" {
		p.Name = meta
	}
	if p.Username == "" {
		var old struct {
			Login string `json:"login"`
		}
		if json.Unmarshal(raw, &old) == nil && old.Login != "" {
			p.Username = old.Login
		}
	}
	return p
}

func parseAuthPayload(raw []byte, meta string) AuthPayload {
	var p AuthPayload
	_ = json.Unmarshal(raw, &p)
	// backward-compat with old OTPPayload {"secret":...,"label":...}
	if p.Name == "" {
		p.Name = meta
	}
	return p
}

func parseCardPayload(raw []byte, meta string) CardPayload {
	var p CardPayload
	_ = json.Unmarshal(raw, &p)
	if p.Name == "" {
		p.Name = meta
	}
	return p
}

func parseIdentityPayload(raw []byte, meta string) IdentityPayload {
	var p IdentityPayload
	_ = json.Unmarshal(raw, &p)
	if p.Name == "" {
		p.Name = meta
	}
	return p
}

func parseNotePayload(raw []byte, meta string) NotePayload {
	var p NotePayload
	_ = json.Unmarshal(raw, &p)
	if p.Name == "" {
		p.Name = meta
	}
	if p.Content == "" {
		// raw text fallback
		p.Content = string(raw)
	}
	return p
}

// SSHKeyPayload stores an SSH key pair. Stored as ItemType_TEXT with ssh_key=true.
type SSHKeyPayload struct {
	Name       string `json:"name"`
	KeyType    string `json:"key_type"`    // "ed25519", "rsa", "ecdsa"
	PrivateKey string `json:"private_key"` // full PEM content
	PublicKey  string `json:"public_key,omitempty"`
	Comment    string `json:"comment,omitempty"`
	SSHKey     bool   `json:"ssh_key"` // discriminator — always true
}

func parseSSHKeyPayload(raw []byte, meta string) SSHKeyPayload {
	var p SSHKeyPayload
	_ = json.Unmarshal(raw, &p)
	if p.Name == "" {
		p.Name = meta
	}
	return p
}

// FilePayload stores an encrypted binary file attachment.
// Stored as ItemType_BINARY with IsFile=true discriminator,
// similar to how SSHKeyPayload uses ItemType_TEXT + SSHKey=true.
type FilePayload struct {
	Name     string `json:"name"`
	FileName string `json:"file_name"` // original filename
	MimeType string `json:"mime_type"`
	Size     int64  `json:"size"`
	Data     []byte `json:"data"`    // raw file bytes
	IsFile   bool   `json:"is_file"` // discriminator — always true
}

func parseFilePayload(raw []byte, meta string) FilePayload {
	var p FilePayload
	_ = json.Unmarshal(raw, &p)
	if p.Name == "" {
		p.Name = meta
	}
	return p
}

// FormatFileSize returns a human-readable file size string.
func FormatFileSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
