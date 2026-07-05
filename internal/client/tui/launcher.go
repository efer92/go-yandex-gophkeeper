package tui

import (
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/efer92/go-yandex-gophkeeper/internal/client/config"
	"github.com/efer92/go-yandex-gophkeeper/internal/shared/version"
)

// Launcher is the top-level bubbletea model.
// It starts with AuthModel when the user is not logged in,
// then seamlessly switches to the vault Model after auth succeeds.
type Launcher struct {
	auth  *AuthModel
	vault *Model
	ready bool // true when showing the vault UI
}

// NewLauncher creates the launcher.
// If cfg already has a valid access token, it skips auth and goes straight
// to the vault model. Otherwise it starts with the auth flow.
func NewLauncher(cfg *config.Config) (*Launcher, error) {
	if cfg.AccessToken != "" {
		m, err := New(cfg)
		if err != nil {
			return nil, err
		}
		return &Launcher{vault: m, ready: true}, nil
	}
	return &Launcher{auth: NewAuthModel(cfg)}, nil
}

func setTitle(title string) tea.Cmd {
	return func() tea.Msg {
		// \x1b]0; sets both icon name and window title atomically.
		_, _ = os.Stdout.WriteString("\x1b]0;" + title + "\x07")
		return nil
	}
}

func (l *Launcher) Init() tea.Cmd {
	title := "GophKeeper | Version: " + version.Version + " | Build: " + version.BuildDate
	if l.ready {
		return tea.Batch(setTitle(title), l.vault.Init())
	}
	return tea.Batch(setTitle(title), l.auth.Init())
}

func (l *Launcher) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Handle auth→vault transition
	if !l.ready {
		if done, ok := msg.(authDoneMsg); ok {
			// Auth succeeded — build vault model and switch
			m, err := New(done.cfg)
			if err != nil {
				l.auth.errMsg = "ошибка инициализации: " + err.Error()
				return l, nil
			}
			l.vault = m
			l.ready = true
			// Propagate window size
			if l.auth != nil {
				l.vault.width = l.auth.width
				l.vault.height = l.auth.height
			}
			return l, l.vault.Init()
		}

		// Let auth model handle special messages before generic Update
		if handled, cmd := l.auth.handleSpecialMsg(msg); handled {
			return l, cmd
		}

		next, cmd := l.auth.Update(msg)
		l.auth = next.(*AuthModel)
		return l, cmd
	}

	// Vault model
	next, cmd := l.vault.Update(msg)
	l.vault = next.(*Model)
	return l, cmd
}

func (l *Launcher) View() string {
	if l.ready {
		return l.vault.View()
	}
	return l.auth.View()
}
