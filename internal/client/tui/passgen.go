package tui

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
)

type passGenRefreshMsg string // new preview value

// ── Tabs ─────────────────────────────────────────────────────────────────────

type passGenTab int

const (
	tabPassword   passGenTab = iota
	tabPassphrase            // diceware-style
)

// ── Focused field indices ─────────────────────────────────────────────────────

const (
	// Password tab
	pgFldLength = iota
	pgFldUpper
	pgFldLower
	pgFldDigits
	pgFldSymbols
	pgFldMinDigits
	pgFldMinSymbols
	pgFldAmbig
	pgPasswordFields

	// Passphrase tab (separate numbering used at runtime)
	ppFldWords = iota - pgPasswordFields
	ppFldSep
	ppFldCapitalize
	ppFldIncludeNum
	ppPassphraseFields
)

var passGenSeps = []string{"-", "_", ".", " ", ""}

func passGenSepLabel(idx int) string {
	switch passGenSeps[idx] {
	case "":
		return "нет"
	case " ":
		return "пробел"
	default:
		return passGenSeps[idx]
	}
}

// ── State ─────────────────────────────────────────────────────────────────────

type passGenState struct {
	tab   passGenTab
	focus int // focused field index within current tab

	// Password tab
	length     int
	useUpper   bool
	useLower   bool
	useDigits  bool
	useSymbols bool
	minDigits  int
	minSymbols int
	avoidAmbig bool

	// Passphrase tab
	wordCount    int
	separatorIdx int
	capitalize   bool
	includeNum   bool

	// Current preview string (raw, uncolored)
	preview string

	// -1 = standalone (copy to clipboard on confirm)
	// >= 0 = form field index to fill
	targetFieldIdx int
}

func newPassGenState(targetFieldIdx int) *passGenState {
	s := &passGenState{
		tab:            tabPassword,
		focus:          pgFldLength,
		length:         20,
		useUpper:       true,
		useLower:       true,
		useDigits:      true,
		useSymbols:     true,
		minDigits:      1,
		minSymbols:     1,
		avoidAmbig:     false,
		wordCount:      5,
		separatorIdx:   0,
		capitalize:     true,
		includeNum:     true,
		targetFieldIdx: targetFieldIdx,
	}
	s.refresh()
	return s
}

// refreshCmd generates a new password in a goroutine and sends passGenRefreshMsg.
func (s *passGenState) refreshCmd() tea.Cmd {
	// snapshot settings to avoid data race
	tab := s.tab
	opts := crypto.PasswordOpts{Length: s.length, Upper: s.useUpper, Digits: s.useDigits, Symbols: s.useSymbols, NoAmbiguous: s.avoidAmbig}
	minD, minS := s.minDigits, s.minSymbols
	ppOpts := crypto.PassphraseOpts{Words: s.wordCount, Separator: passGenSeps[s.separatorIdx], Capitalize: s.capitalize, IncludeNum: s.includeNum}
	return func() tea.Msg {
		var preview string
		switch tab {
		case tabPassword:
			for i := 0; i < 30; i++ {
				pwd, err := crypto.GeneratePassword(opts)
				if err != nil {
					return passGenRefreshMsg("ошибка")
				}
				if passGenMeetsMinimums(pwd, minD, minS) {
					return passGenRefreshMsg(pwd)
				}
				preview = pwd
			}
			return passGenRefreshMsg(preview)
		case tabPassphrase:
			pwd, err := crypto.GeneratePassphrase(ppOpts)
			if err != nil {
				return passGenRefreshMsg("ошибка")
			}
			return passGenRefreshMsg(pwd)
		}
		return passGenRefreshMsg("")
	}
}

// refresh generates a new preview based on the current settings (sync, used only on init).
func (s *passGenState) refresh() {
	switch s.tab {
	case tabPassword:
		opts := crypto.PasswordOpts{
			Length:      s.length,
			Upper:       s.useUpper,
			Digits:      s.useDigits,
			Symbols:     s.useSymbols,
			NoAmbiguous: s.avoidAmbig,
		}
		// Retry up to 30 times to meet minimums
		for i := 0; i < 30; i++ {
			pwd, err := crypto.GeneratePassword(opts)
			if err != nil {
				s.preview = "ошибка генерации"
				return
			}
			if passGenMeetsMinimums(pwd, s.minDigits, s.minSymbols) {
				s.preview = pwd
				return
			}
		}
		// Fallback: generate without minimum constraint
		pwd, err := crypto.GeneratePassword(opts)
		if err != nil {
			s.preview = "ошибка генерации"
			return
		}
		s.preview = pwd
	case tabPassphrase:
		pwd, err := crypto.GeneratePassphrase(crypto.PassphraseOpts{
			Words:      s.wordCount,
			Separator:  passGenSeps[s.separatorIdx],
			Capitalize: s.capitalize,
			IncludeNum: s.includeNum,
		})
		if err != nil {
			s.preview = "ошибка генерации"
			return
		}
		s.preview = pwd
	}
}

func passGenMeetsMinimums(pwd string, minDigits, minSymbols int) bool {
	d, sym := 0, 0
	for _, ch := range pwd {
		switch {
		case unicode.IsDigit(ch):
			d++
		case !unicode.IsLetter(ch):
			sym++
		}
	}
	return d >= minDigits && sym >= minSymbols
}

func (s *passGenState) maxFocus() int {
	if s.tab == tabPassphrase {
		return ppPassphraseFields - 1
	}
	return pgPasswordFields - 1
}

func (s *passGenState) adjustFocused(delta int) {
	switch s.tab {
	case tabPassword:
		switch s.focus {
		case pgFldLength:
			s.length += delta
			if s.length < 4 {
				s.length = 4
			}
			if s.length > 128 {
				s.length = 128
			}
		case pgFldMinDigits:
			s.minDigits += delta
			if s.minDigits < 0 {
				s.minDigits = 0
			}
			if s.minDigits > s.length/2 {
				s.minDigits = s.length / 2
			}
		case pgFldMinSymbols:
			s.minSymbols += delta
			if s.minSymbols < 0 {
				s.minSymbols = 0
			}
			if s.minSymbols > s.length/2 {
				s.minSymbols = s.length / 2
			}
		}
	case tabPassphrase:
		switch s.focus {
		case ppFldWords:
			s.wordCount += delta
			if s.wordCount < 2 {
				s.wordCount = 2
			}
			if s.wordCount > 10 {
				s.wordCount = 10
			}
		case ppFldSep:
			s.separatorIdx = (s.separatorIdx + delta + len(passGenSeps)) % len(passGenSeps)
		}
	}
}

func (s *passGenState) toggleFocused() {
	switch s.tab {
	case tabPassword:
		switch s.focus {
		case pgFldUpper:
			s.useUpper = !s.useUpper
		case pgFldLower:
			s.useLower = !s.useLower
		case pgFldDigits:
			s.useDigits = !s.useDigits
		case pgFldSymbols:
			s.useSymbols = !s.useSymbols
		case pgFldAmbig:
			s.avoidAmbig = !s.avoidAmbig
		}
	case tabPassphrase:
		switch s.focus {
		case ppFldCapitalize:
			s.capitalize = !s.capitalize
		case ppFldIncludeNum:
			s.includeNum = !s.includeNum
		}
	}
}

// ── Key handler ───────────────────────────────────────────────────────────────

func (m *Model) handlePassGenKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	pg := m.passGen
	switch msg.String() {
	case "esc":
		m.mode = modeForm
		if pg.targetFieldIdx < 0 {
			m.mode = modeList
		}
		m.passGen = nil
		return m, nil

	case "enter":
		if pg.targetFieldIdx >= 0 && m.form != nil && pg.targetFieldIdx < len(m.form.fields) {
			// Fill form field
			m.form.fields[pg.targetFieldIdx].input.SetValue(pg.preview)
		} else if pg.targetFieldIdx < 0 {
			// Standalone: copy to clipboard
			_ = clipboard.WriteAll(pg.preview)
			m.passGen = nil
			m.mode = modeList
			m.setToast("Скопировано в буфер ✓")
			return m, nil
		}
		m.mode = modeForm
		m.passGen = nil
		return m, nil

	case "1":
		pg.tab = tabPassword
		pg.focus = 0
		return m, pg.refreshCmd()
	case "2":
		pg.tab = tabPassphrase
		pg.focus = 0
		return m, pg.refreshCmd()

	case "r", "ctrl+g":
		return m, pg.refreshCmd()

	case "up", "k", "shift+tab":
		if pg.focus > 0 {
			pg.focus--
		} else {
			pg.focus = pg.maxFocus()
		}
	case "down", "j", "tab":
		if pg.focus < pg.maxFocus() {
			pg.focus++
		} else {
			pg.focus = 0
		}

	case "left", "h", "-":
		pg.adjustFocused(-1)
		return m, pg.refreshCmd()
	case "right", "l", "+", "=":
		pg.adjustFocused(+1)
		return m, pg.refreshCmd()

	case " ":
		pg.toggleFocused()
		return m, pg.refreshCmd()
	}
	return m, nil
}

// ── View ──────────────────────────────────────────────────────────────────────

func (m *Model) viewPassGen() string {
	pg := m.passGen
	const panelW = 62
	const innerW = panelW - 8 // accounting for padding(2*2) + border(2)

	var sb strings.Builder

	// ── Title ──
	sb.WriteString(dimStyle.Render("🎲 ") + passGenFocusedStyle.Render("Password Generator") + "\n\n")

	// ── Tabs ──
	tab1 := "  Password  "
	tab2 := "  Passphrase  "
	if pg.tab == tabPassword {
		sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
			passGenTabActiveStyle.Render(tab1),
			passGenTabStyle.Render(tab2),
		))
	} else {
		sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
			passGenTabStyle.Render(tab1),
			passGenTabActiveStyle.Render(tab2),
		))
	}
	sb.WriteString("\n\n")

	// ── Colorized preview ──
	preview := colorizePassword(pg.preview)
	sb.WriteString(passGenPreviewStyle.Width(innerW).Render(preview) + "\n")
	sb.WriteString(strengthBar(pg.preview, innerW) + "\n\n")

	// ── Options ──
	if pg.tab == tabPassword {
		sb.WriteString(renderPasswordOpts(pg))
	} else {
		sb.WriteString(renderPassphraseOpts(pg))
	}

	// ── Footer hints ──
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("  ↑↓ field   ←→ value   Spc toggle   r refresh") + "\n")
	sb.WriteString(dimStyle.Render("  1/2 type   Enter use   Esc cancel"))

	return passGenPanelStyle.Width(panelW).Render(sb.String())
}

func renderPasswordOpts(pg *passGenState) string {
	var sb strings.Builder

	sb.WriteString(pgRowRaw(pg.focus == pgFldLength,
		fmt.Sprintf("Length: %s  %s",
			pgNumVal(pg.focus == pgFldLength, pg.length),
			dimStyle.Render("[←→]"),
		)) + "\n\n")

	sb.WriteString(passGenLabelStyle.Render("  Include:") + "\n")

	col1 := lipgloss.JoinVertical(lipgloss.Left,
		pgCheck(pg.focus == pgFldUpper, pg.useUpper, "A-Z  uppercase"),
		pgCheck(pg.focus == pgFldDigits, pg.useDigits, "0-9  digits"),
	)
	col2 := lipgloss.JoinVertical(lipgloss.Left,
		pgCheck(pg.focus == pgFldLower, pg.useLower, "a-z  lowercase"),
		pgCheck(pg.focus == pgFldSymbols, pg.useSymbols, "!@#$  symbols"),
	)
	sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(28).Render(col1),
		col2,
	) + "\n\n")

	sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(28).Render(
			pgRowRaw(pg.focus == pgFldMinDigits, fmt.Sprintf("Min digits: %s  %s",
				pgNumVal(pg.focus == pgFldMinDigits, pg.minDigits), dimStyle.Render("[←→]"))),
		),
		pgRowRaw(pg.focus == pgFldMinSymbols, fmt.Sprintf("Min symbols: %s  %s",
			pgNumVal(pg.focus == pgFldMinSymbols, pg.minSymbols), dimStyle.Render("[←→]"))),
	) + "\n\n")

	sb.WriteString(pgCheck(pg.focus == pgFldAmbig, pg.avoidAmbig, "Avoid ambiguous (l 1 I O 0)") + "\n")

	return sb.String()
}

func renderPassphraseOpts(pg *passGenState) string {
	sepLabel := passGenSepLabel(pg.separatorIdx)
	var out strings.Builder
	out.WriteString(pgRowRaw(pg.focus == ppFldWords,
		fmt.Sprintf("Words:  %s  %s",
			pgNumVal(pg.focus == ppFldWords, pg.wordCount),
			dimStyle.Render("[←→]"),
		),
	) + "\n\n")
	out.WriteString(pgRowRaw(pg.focus == ppFldSep,
		fmt.Sprintf("Separator:  %s  %s",
			pgStrVal(pg.focus == ppFldSep, fmt.Sprintf("« %s »", sepLabel)),
			dimStyle.Render("[←→]"),
		),
	) + "\n\n")
	out.WriteString("  " + pgCheck(pg.focus == ppFldCapitalize, pg.capitalize, "Capitalize words") + "\n")
	out.WriteString("  " + pgCheck(pg.focus == ppFldIncludeNum, pg.includeNum, "Include number") + "\n")
	return out.String()
}

// ── Small helpers ─────────────────────────────────────────────────────────────

func pgRowRaw(focused bool, content string) string {
	if focused {
		return passGenFocusedStyle.Render("❯ ") + content
	}
	return "  " + content
}

func pgNumberStyle(focused bool, n int) string {
	s := fmt.Sprintf("%d", n)
	if focused {
		return passGenFocusedStyle.Render(fmt.Sprintf("[%s]", s))
	}
	return passGenLabelStyle.Render(fmt.Sprintf("[%s]", s))
}

func pgNumVal(focused bool, n int) string {
	return pgNumberStyle(focused, n)
}

func pgStrVal(focused bool, s string) string {
	if focused {
		return passGenFocusedStyle.Render(s)
	}
	return passGenLabelStyle.Render(s)
}

func pgCheck(focused, checked bool, label string) string {
	var box string
	if checked {
		box = passGenCheckOnStyle.Render("[✓]")
	} else {
		box = passGenCheckOffStyle.Render("[ ]")
	}
	var lbl string
	if focused {
		lbl = passGenFocusedStyle.Render(label)
	} else {
		lbl = passGenLabelStyle.Render(label)
	}
	if focused {
		return passGenFocusedStyle.Render("❯ ") + box + " " + lbl
	}
	return "  " + box + " " + lbl
}

// colorizePassword colors each character by type for the preview.
func colorizePassword(pwd string) string {
	var sb strings.Builder
	for _, ch := range pwd {
		s := string(ch)
		switch {
		case ch >= 'A' && ch <= 'Z':
			sb.WriteString(pwdUpperStyle.Render(s))
		case ch >= 'a' && ch <= 'z':
			sb.WriteString(pwdLowerStyle.Render(s))
		case ch >= '0' && ch <= '9':
			sb.WriteString(pwdDigitStyle.Render(s))
		default:
			sb.WriteString(pwdSymbolStyle.Render(s))
		}
	}
	return sb.String()
}

// strengthBar renders a visual password strength indicator.
func strengthBar(pwd string, width int) string {
	score, label, style := passwordStrength(pwd)
	barFilled := score * width / 100
	bar := strings.Repeat("█", barFilled) + strings.Repeat("░", width-barFilled)
	return style.Render(bar) + "  " + style.Render(label)
}

// passwordStrength returns (score 0-100, label, style).
func passwordStrength(pwd string) (int, string, lipgloss.Style) {
	if len(pwd) == 0 {
		return 0, "", dimStyle
	}
	score := 0
	hasUpper, hasLower, hasDigit, hasSym := false, false, false, false
	for _, ch := range pwd {
		switch {
		case ch >= 'A' && ch <= 'Z':
			hasUpper = true
		case ch >= 'a' && ch <= 'z':
			hasLower = true
		case ch >= '0' && ch <= '9':
			hasDigit = true
		default:
			hasSym = true
		}
	}
	// Length score
	l := len([]rune(pwd))
	switch {
	case l >= 24:
		score += 40
	case l >= 16:
		score += 30
	case l >= 12:
		score += 20
	case l >= 8:
		score += 10
	}
	// Complexity score
	if hasUpper {
		score += 15
	}
	if hasLower {
		score += 15
	}
	if hasDigit {
		score += 15
	}
	if hasSym {
		score += 15
	}
	switch {
	case score >= 85:
		return score, "Очень сильный", strengthStrongStyle
	case score >= 65:
		return score, "Сильный", strengthGoodStyle
	case score >= 45:
		return score, "Средний", strengthFairStyle
	case score >= 25:
		return score, "Слабый", strengthWeakStyle
	default:
		return score, "Очень слабый", strengthVeryWeakStyle
	}
}
