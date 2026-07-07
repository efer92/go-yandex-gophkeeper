package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	authpb "github.com/efer92/go-yandex-gophkeeper/gen/auth"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/config"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/grpcclient"
	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
)

// ─── Auth steps ──────────────────────────────────────────────────────────────

type authStep int

const (
	authStepServer   authStep = iota // enter / confirm server address
	authStepMenu                     // login or register
	authStepLogin                    // username + password
	authStepRegister                 // username + email + password + confirm
	authStepLoading                  // waiting for gRPC
	authStepMFA                      // TOTP code needed
)

// authDoneMsg is sent after a successful login/register.
// The launcher replaces AuthModel with the vault Model.
type authDoneMsg struct{ cfg *config.Config }

type authErrMsg string

// ─── AuthModel ───────────────────────────────────────────────────────────────

// AuthModel is the bubbletea model that drives the authentication flow
// (server selection → login/register menu → credential entry → optional MFA).
type AuthModel struct {
	cfg    *config.Config
	step   authStep
	width  int
	height int

	// server step
	serverInput textinput.Model

	// menu step
	menuIdx int // 0 = login, 1 = register

	// login / register fields
	inputs   []textinput.Model
	focusIdx int

	// mfa
	mfaSessionID string

	errMsg  string
	loading bool
}

// NewAuthModel creates an AuthModel starting at the server-selection step.
func NewAuthModel(cfg *config.Config) *AuthModel {
	srv := textinput.New()
	srv.Placeholder = "localhost:50051"
	srv.SetValue(cfg.ServerAddr)
	srv.Focus()
	srv.Width = 40
	srv.PromptStyle = lipgloss.NewStyle().Foreground(c(colorBlue))
	srv.TextStyle = lipgloss.NewStyle().Foreground(c(colorText))

	return &AuthModel{
		cfg:         cfg,
		step:        authStepServer,
		serverInput: srv,
	}
}

func (m *AuthModel) Init() tea.Cmd {
	return textinput.Blink
}

// ─── Update ──────────────────────────────────────────────────────────────────

func (m *AuthModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

	case authDoneMsg:
		// reached only when used standalone; launcher intercepts first
		return m, tea.Quit

	case authErrMsg:
		m.loading = false
		m.errMsg = string(msg)
		m.step = _stepBeforeLoading
		// re-focus last input
		if len(m.inputs) > 0 {
			m.inputs[m.focusIdx].Focus()
		}

	case tea.KeyMsg:
		m.errMsg = ""
		switch m.step {
		case authStepServer:
			return m, m.handleServerKey(msg)
		case authStepMenu:
			return m, m.handleMenuKey(msg)
		case authStepLogin, authStepRegister:
			return m, m.handleFormKey(msg)
		case authStepMFA:
			return m, m.handleMFAKey(msg)
		}
	}

	// forward key to active input
	if m.step == authStepServer {
		var cmd tea.Cmd
		m.serverInput, cmd = m.serverInput.Update(msg)
		return m, cmd
	}
	if m.step == authStepLogin || m.step == authStepRegister || m.step == authStepMFA {
		var cmds []tea.Cmd
		for i := range m.inputs {
			var c tea.Cmd
			m.inputs[i], c = m.inputs[i].Update(msg)
			cmds = append(cmds, c)
		}
		return m, tea.Batch(cmds...)
	}

	return m, nil
}

// stepBeforeLoading remembers which step to return to on error
var _stepBeforeLoading authStep

func (m *AuthModel) handleServerKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "ctrl+c", "q":
		return tea.Quit
	case "enter":
		addr := strings.TrimSpace(m.serverInput.Value())
		if addr == "" {
			addr = m.serverInput.Placeholder
		}
		m.cfg.ServerAddr = addr
		m.step = authStepMenu
		m.menuIdx = 0
	default:
		var cmd tea.Cmd
		m.serverInput, cmd = m.serverInput.Update(msg)
		return cmd
	}
	return nil
}

func (m *AuthModel) handleMenuKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "ctrl+c":
		return tea.Quit
	case "esc":
		m.step = authStepServer
		m.serverInput.Focus()
	case "up", "k":
		if m.menuIdx > 0 {
			m.menuIdx--
		}
	case "down", "j":
		if m.menuIdx < 1 {
			m.menuIdx++
		}
	case "1":
		m.menuIdx = 0
		m.openLoginForm()
	case "2":
		m.menuIdx = 1
		m.openRegisterForm()
	case "enter":
		if m.menuIdx == 0 {
			m.openLoginForm()
		} else {
			m.openRegisterForm()
		}
	}
	return nil
}

func (m *AuthModel) handleFormKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "ctrl+c":
		return tea.Quit
	case "esc":
		m.step = authStepMenu
		m.inputs = nil
	case "tab", "down":
		m.nextField()
	case "shift+tab", "up":
		m.prevField()
	case "enter":
		if m.focusIdx == len(m.inputs)-1 {
			return m.submitForm()
		}
		m.nextField()
	default:
		var cmds []tea.Cmd
		for i := range m.inputs {
			var c tea.Cmd
			m.inputs[i], c = m.inputs[i].Update(msg)
			cmds = append(cmds, c)
		}
		return tea.Batch(cmds...)
	}
	return nil
}

func (m *AuthModel) handleMFAKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "ctrl+c":
		return tea.Quit
	case "esc":
		m.step = authStepMenu
		m.inputs = nil
	case "enter":
		return m.submitMFA()
	default:
		var cmds []tea.Cmd
		for i := range m.inputs {
			var c tea.Cmd
			m.inputs[i], c = m.inputs[i].Update(msg)
			cmds = append(cmds, c)
		}
		return tea.Batch(cmds...)
	}
	return nil
}

// ─── Form helpers ─────────────────────────────────────────────────────────────

func mkAuthInput(placeholder, value string, secret bool) textinput.Model {
	t := textinput.New()
	t.Placeholder = placeholder
	t.SetValue(value)
	t.Width = 36
	t.PromptStyle = lipgloss.NewStyle().Foreground(c(colorBlue))
	t.TextStyle = lipgloss.NewStyle().Foreground(c(colorText))
	if secret {
		t.EchoMode = textinput.EchoPassword
		t.EchoCharacter = '•'
	}
	return t
}

func (m *AuthModel) openLoginForm() {
	m.step = authStepLogin
	user := mkAuthInput("username", m.cfg.Username, false)
	user.Focus()
	pwd := mkAuthInput("master password", "", true)
	m.inputs = []textinput.Model{user, pwd}
	m.focusIdx = 0
}

func (m *AuthModel) openRegisterForm() {
	m.step = authStepRegister
	user := mkAuthInput("username", "", false)
	user.Focus()
	email := mkAuthInput("email (optional)", "", false)
	pwd := mkAuthInput("master password", "", true)
	confirm := mkAuthInput("confirm password", "", true)
	m.inputs = []textinput.Model{user, email, pwd, confirm}
	m.focusIdx = 0
}

func (m *AuthModel) nextField() {
	m.inputs[m.focusIdx].Blur()
	m.focusIdx = (m.focusIdx + 1) % len(m.inputs)
	m.inputs[m.focusIdx].Focus()
}

func (m *AuthModel) prevField() {
	m.inputs[m.focusIdx].Blur()
	m.focusIdx = (m.focusIdx - 1 + len(m.inputs)) % len(m.inputs)
	m.inputs[m.focusIdx].Focus()
}

// ─── gRPC calls ───────────────────────────────────────────────────────────────

func (m *AuthModel) submitForm() tea.Cmd {
	m.loading = true
	_stepBeforeLoading = m.step

	if m.step == authStepLogin {
		username := m.inputs[0].Value()
		password := m.inputs[1].Value()
		cfg := m.cfg
		return func() tea.Msg {
			return doLogin(cfg, username, password)
		}
	}

	// register
	username := m.inputs[0].Value()
	email := m.inputs[1].Value()
	password := m.inputs[2].Value()
	confirm := m.inputs[3].Value()
	if password != confirm {
		m.loading = false
		return func() tea.Msg { return authErrMsg("пароли не совпадают") }
	}
	if username == "" || password == "" {
		m.loading = false
		return func() tea.Msg { return authErrMsg("заполните обязательные поля") }
	}
	cfg := m.cfg
	return func() tea.Msg {
		return doRegister(cfg, username, email, password)
	}
}

func (m *AuthModel) submitMFA() tea.Cmd {
	m.loading = true
	code := m.inputs[0].Value()
	sessionID := m.mfaSessionID
	cfg := m.cfg
	return func() tea.Msg {
		return doMFA(cfg, sessionID, code)
	}
}

// ─── async gRPC helpers ───────────────────────────────────────────────────────

// needsMFAMsg is sent when server requests TOTP verification.
type needsMFAMsg struct{ sessionID string }

func doLogin(cfg *config.Config, username, password string) (msg tea.Msg) {
	defer func() {
		if r := recover(); r != nil {
			msg = authErrMsg("Сервер недоступен")
		}
	}()
	client, err := grpcclient.New(cfg)
	if err != nil {
		return authErrMsg(fmt.Sprintf("подключение: %v", err))
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.AuthSvc.Login(ctx, authpb.LoginRequest_builder{
		Username: username,
		Password: password,
	}.Build())
	if err != nil {
		return authErrMsg(fmt.Sprintf("Sign in failed: %v", grpcMsg(err)))
	}

	if resp.GetNeedsMfa() {
		return needsMFAMsg{sessionID: resp.GetSessionId()}
	}

	cfg.Username = username
	cfg.AccessToken = resp.GetAccessToken()
	cfg.RefreshToken = resp.GetRefreshToken()
	_ = config.Save(cfg)
	return authDoneMsg{cfg: cfg}
}

func doRegister(cfg *config.Config, username, email, password string) (msg tea.Msg) {
	defer func() {
		if r := recover(); r != nil {
			msg = authErrMsg("Сервер недоступен")
		}
	}()
	kdfParams, err := crypto.DefaultKDFParams()
	if err != nil {
		return authErrMsg(fmt.Sprintf("генерация KDF: %v", err))
	}
	masterKey := crypto.DeriveKey([]byte(password), kdfParams)
	encKey, _ := crypto.StretchKey(masterKey)
	vaultKey, err := crypto.GenerateVaultSymKey()
	if err != nil {
		return authErrMsg(fmt.Sprintf("генерация ключа: %v", err))
	}
	sealedKey, err := crypto.SealVaultSymKey(vaultKey, encKey)
	if err != nil {
		return authErrMsg(fmt.Sprintf("шифрование ключа: %v", err))
	}
	kdfJSON, err := crypto.MarshalKDFParams(kdfParams)
	if err != nil {
		return authErrMsg(fmt.Sprintf("kdf params: %v", err))
	}

	client, err := grpcclient.New(cfg)
	if err != nil {
		return authErrMsg(fmt.Sprintf("подключение: %v", err))
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.AuthSvc.Register(ctx, authpb.RegisterRequest_builder{
		Username:      username,
		Email:         email,
		Password:      password,
		VaultSymKey:   sealedKey,
		KdfParamsJson: kdfJSON,
	}.Build())
	if err != nil {
		return authErrMsg(fmt.Sprintf("Registration failed: %v", grpcMsg(err)))
	}
	_ = resp // RegisterResponse only returns UserId

	// Register doesn't return tokens — do an immediate login
	return doLogin(cfg, username, password)
}

func doMFA(cfg *config.Config, sessionID, code string) (msg tea.Msg) {
	defer func() {
		if r := recover(); r != nil {
			msg = authErrMsg("Сервер недоступен")
		}
	}()
	client, err := grpcclient.New(cfg)
	if err != nil {
		return authErrMsg(fmt.Sprintf("подключение: %v", err))
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.AuthSvc.VerifyMFA(ctx, authpb.VerifyMFARequest_builder{
		SessionId: sessionID,
		TotpCode:  code,
	}.Build())
	if err != nil {
		return authErrMsg(fmt.Sprintf("MFA failed: %v", grpcMsg(err)))
	}

	cfg.AccessToken = resp.GetAccessToken()
	cfg.RefreshToken = resp.GetRefreshToken()
	_ = config.Save(cfg)
	return authDoneMsg{cfg: cfg}
}

// grpcMsg strips gRPC status prefix for cleaner error display.
// Connection-level errors are reported as "Сервер недоступен".
func grpcMsg(err error) string {
	s := err.Error()
	if strings.Contains(s, "connection refused") ||
		strings.Contains(s, "no such host") ||
		strings.Contains(s, "deadline exceeded") ||
		strings.Contains(s, "Unavailable") {
		return "Server unavailable"
	}
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}

// ─── View ────────────────────────────────────────────────────────────────────

func (m *AuthModel) View() string {
	if m.width == 0 {
		return ""
	}
	bg := lipgloss.NewStyle().
		Background(c(colorBase)).
		Width(m.width)

	var sb strings.Builder

	sb.WriteString("\n\n")

	// ── Title ─────────────────────────────────────────────────────────────
	logo := lipgloss.NewStyle().
		Foreground(c(colorMauve)).Bold(true).
		Background(c(colorSurface0)).Padding(0, 2).
		Render("🔒 GophKeeper")
	logoLine := lipgloss.NewStyle().Width(m.width).Align(lipgloss.Center).Render(logo)
	sb.WriteString(logoLine + "\n\n")

	// ── Step content (centred panel) ──────────────────────────────────────
	content := m.renderStep()
	panelW := 50
	if m.width < 60 {
		panelW = m.width - 4
	}
	panel := lipgloss.NewStyle().
		Background(c(colorMantle)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(c(colorSurface1)).
		Padding(1, 3).
		Width(panelW)

	centred := lipgloss.NewStyle().Width(m.width).Align(lipgloss.Center)
	sb.WriteString(centred.Render(panel.Render(content)) + "\n")

	// ── Error ─────────────────────────────────────────────────────────────
	if m.errMsg != "" {
		errLine := lipgloss.NewStyle().
			Foreground(c(colorRed)).Bold(true).
			Width(m.width).Align(lipgloss.Center).
			Render("✗  " + m.errMsg)
		sb.WriteString("\n" + errLine + "\n")
	}

	// ── Footer ────────────────────────────────────────────────────────────
	var hint string
	switch m.step {
	case authStepServer:
		hint = "Enter — continue   •   Ctrl+C — quit"
	case authStepMenu:
		hint = "↑↓ — select   •   Enter — confirm   •   Esc — back"
	case authStepLogin:
		hint = "Tab — next field   •   Enter — sign in   •   Esc — back"
	case authStepRegister:
		hint = "Tab — next field   •   Enter — create account   •   Esc — back"
	case authStepMFA:
		hint = "Enter — confirm   •   Esc — back"
	case authStepLoading:
		hint = "Please wait..."
	}
	footer := dimStyle.Width(m.width).Align(lipgloss.Center).Render(hint)
	sb.WriteString("\n" + footer)

	body := bg.Render(sb.String())
	return lipgloss.Place(m.width, m.height,
		lipgloss.Left, lipgloss.Top,
		body,
		lipgloss.WithWhitespaceBackground(c(colorBase)),
	)
}

func (m *AuthModel) renderStep() string {
	var sb strings.Builder

	switch m.step {
	case authStepServer:
		sb.WriteString(lipgloss.NewStyle().Foreground(c(colorBlue)).Bold(true).Render("Server Address") + "\n\n")
		sb.WriteString(m.serverInput.View() + "\n")

	case authStepMenu:
		sb.WriteString(dimStyle.Render(m.cfg.ServerAddr) + "\n\n")
		opts := []string{"Sign In", "Create Account"}
		for i, opt := range opts {
			if i == m.menuIdx {
				sb.WriteString(lipgloss.NewStyle().
					Foreground(c(colorBlue)).Bold(true).
					Background(c(colorSurface0)).Padding(0, 1).
					Render("▶ "+opt) + "\n")
			} else {
				sb.WriteString(dimStyle.Padding(0, 1).Render("  "+opt) + "\n")
			}
		}

	case authStepLogin:
		sb.WriteString(lipgloss.NewStyle().Foreground(c(colorMauve)).Bold(true).Render("Sign In") + "\n\n")
		labels := []string{"Username", "Master Password"}
		for i, inp := range m.inputs {
			lStyle := formLabelStyle
			if i == m.focusIdx {
				lStyle = formLabelActiveStyle
			}
			sb.WriteString(lStyle.Render(labels[i]) + "\n")
			sb.WriteString(inp.View() + "\n\n")
		}
		if m.loading {
			sb.WriteString(dimStyle.Render(spinFrames[0] + "  Signing in..."))
		}

	case authStepRegister:
		sb.WriteString(lipgloss.NewStyle().Foreground(c(colorGreen)).Bold(true).Render("Create Account") + "\n\n")
		labels := []string{"Username *", "Email (optional)", "Master Password *", "Confirm Password *"}
		for i, inp := range m.inputs {
			lStyle := formLabelStyle
			if i == m.focusIdx {
				lStyle = formLabelActiveStyle
			}
			sb.WriteString(lStyle.Render(labels[i]) + "\n")
			sb.WriteString(inp.View() + "\n\n")
		}
		if m.loading {
			sb.WriteString(dimStyle.Render(spinFrames[0] + "  Creating account..."))
		}

	case authStepMFA:
		sb.WriteString(lipgloss.NewStyle().Foreground(c(colorYellow)).Bold(true).Render("Two-Factor Authentication") + "\n\n")
		sb.WriteString(dimStyle.Render("Enter the code from your authenticator app:") + "\n\n")
		if len(m.inputs) > 0 {
			sb.WriteString(m.inputs[0].View() + "\n")
		}

	case authStepLoading:
		sb.WriteString(dimStyle.Render(spinFrames[0]+"  Please wait...") + "\n")
	}

	return sb.String()
}

// handleAuthUpdate is called from the launcher to catch needsMFAMsg / authDoneMsg.
func (m *AuthModel) handleSpecialMsg(msg tea.Msg) (handled bool, cmd tea.Cmd) {
	switch msg := msg.(type) {
	case needsMFAMsg:
		m.loading = false
		m.mfaSessionID = msg.sessionID
		m.step = authStepMFA
		mfaInput := mkAuthInput("000000", "", false)
		mfaInput.Focus()
		m.inputs = []textinput.Model{mfaInput}
		m.focusIdx = 0
		return true, textinput.Blink
	case authErrMsg:
		m.loading = false
		m.errMsg = string(msg)
		m.step = _stepBeforeLoading
		if len(m.inputs) > 0 && m.focusIdx < len(m.inputs) {
			m.inputs[m.focusIdx].Focus()
		}
		return true, nil
	}
	return false, nil
}
