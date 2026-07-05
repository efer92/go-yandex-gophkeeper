package tui

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// Force TrueColor so styles look identical on macOS/Windows/Ubuntu.
func init() {
	lipgloss.SetColorProfile(termenv.TrueColor)
}

// ── Catppuccin Mocha — fixed dark palette ─────────────────────────────────────

const (
	colorBase     = "#1e1e2e"
	colorMantle   = "#181825"
	colorCrust    = "#11111b"
	colorSurface0 = "#313244"
	colorSurface1 = "#45475a"
	colorSurface2 = "#585b70"
	colorOverlay0 = "#6c7086"
	colorOverlay1 = "#7f849c"
	colorText     = "#cdd6f4"
	colorSubtext0 = "#a6adc8"
	colorSubtext1 = "#bac2de"
	colorBlue     = "#89b4fa"
	colorSapphire = "#74c7ec"
	colorTeal     = "#94e2d5"
	colorGreen    = "#a6e3a1"
	colorYellow   = "#f9e2af"
	colorPeach    = "#fab387"
	colorRed      = "#f38ba8"
	colorMauve    = "#cba6f7"
	colorPink     = "#f5c2e7"
	colorLavender = "#b4befe"

	// Icon background tints
	colorIconLoginBg = "#1e2845"
	colorIconCardBg  = "#1a3020"
	colorIconIdBg    = "#2a1e45"
	colorIconNoteBg  = "#352a10"
	colorIconOtpBg   = "#143025"
	colorIconDefBg   = "#25253a"

	// Selection tints
	colorSelBg      = "#1e2a45"
	colorSelBgDim   = "#222236"
	colorListSelBg  = "#1e2a45"
	colorFolderBg   = "#2a2010"
	colorBadge2FABg = "#102a1e"
)

func c(hex string) lipgloss.Color { return lipgloss.Color(hex) }

// ── Header ────────────────────────────────────────────────────────────────────

var (
	headerStyle = lipgloss.NewStyle().
		Background(c(colorMantle)).
		Foreground(c(colorSubtext1)).
		BorderBottom(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(c(colorSurface0)).
		Padding(0, 2)
)

// ── Sidebar ───────────────────────────────────────────────────────────────────

var (
	sidebarStyle = lipgloss.NewStyle().
			Background(c(colorMantle)).
			BorderRight(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(c(colorSurface0))

	sidebarSectionStyle = lipgloss.NewStyle().
				Background(c(colorMantle)).
				Foreground(c(colorSurface2)).
				Bold(true).
				Padding(0, 0, 0, 2)

	sidebarItemStyle = lipgloss.NewStyle().
				Background(c(colorMantle)).
				Foreground(c(colorSubtext1)).
				Padding(0, 1)

	sidebarSelectedStyle = lipgloss.NewStyle().
				Background(c(colorSelBg)).
				Foreground(c(colorBlue)).
				Bold(true).
				Padding(0, 1)

	sidebarActiveStyle = lipgloss.NewStyle().
				Background(c(colorSelBgDim)).
				Foreground(c(colorSubtext1)).
				Padding(0, 1)

	sidebarDividerStyle = lipgloss.NewStyle().
				Background(c(colorMantle)).
				Foreground(c(colorSurface1)).
				Padding(0, 2)

	sidebarIndicatorFocused = lipgloss.NewStyle().
				Foreground(c(colorBlue)).
				Background(c(colorSelBg))

	sidebarIndicatorBlur = lipgloss.NewStyle().
				Foreground(c(colorSurface1)).
				Background(c(colorSelBgDim))
)

// ── List ──────────────────────────────────────────────────────────────────────

var (
	listHeaderStyle = lipgloss.NewStyle().
			Foreground(c(colorText)).
			Bold(true).
			Padding(0, 2)

	listItemStyle = lipgloss.NewStyle().
			Padding(0, 1)

	listSelectedStyle = lipgloss.NewStyle().
				Background(c(colorListSelBg)).
				Foreground(c(colorText)).
				Padding(0, 1)

	listSubStyle = lipgloss.NewStyle().
			Foreground(c(colorSubtext0)).
			Padding(0, 1)

	listSelectedSubStyle = lipgloss.NewStyle().
				Background(c(colorListSelBg)).
				Foreground(c(colorSubtext0)).
				Padding(0, 1)

	// Icon badge styles
	listIconLoginStyle = lipgloss.NewStyle().
				Background(c(colorIconLoginBg)).
				Foreground(c(colorBlue)).
				Padding(0, 1)

	listIconCardStyle = lipgloss.NewStyle().
				Background(c(colorIconCardBg)).
				Foreground(c(colorGreen)).
				Padding(0, 1)

	listIconIdStyle = lipgloss.NewStyle().
			Background(c(colorIconIdBg)).
			Foreground(c(colorMauve)).
			Padding(0, 1)

	listIconNoteStyle = lipgloss.NewStyle().
				Background(c(colorIconNoteBg)).
				Foreground(c(colorYellow)).
				Padding(0, 1)

	listIconOtpStyle = lipgloss.NewStyle().
				Background(c(colorIconOtpBg)).
				Foreground(c(colorTeal)).
				Padding(0, 1)

	listIconDefaultStyle = lipgloss.NewStyle().
				Background(c(colorIconDefBg)).
				Foreground(c(colorOverlay1)).
				Padding(0, 1)

	// Tags
	listFolderTagStyle = lipgloss.NewStyle().
				Background(c(colorFolderBg)).
				Foreground(c(colorYellow)).
				Padding(0, 1)

	list2FABadgeStyle = lipgloss.NewStyle().
				Background(c(colorBadge2FABg)).
				Foreground(c(colorGreen)).
				Padding(0, 1)
)

// ── Detail panel ──────────────────────────────────────────────────────────────

var (
	detailPanelStyle = lipgloss.NewStyle().
				BorderLeft(true).
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(c(colorSurface0)).
				Background(c(colorMantle)).
				Padding(0, 1)

	detailTitleStyle = lipgloss.NewStyle().
				Foreground(c(colorText)).
				Bold(true)

	detailFolderTagStyle = lipgloss.NewStyle().
				Background(c(colorFolderBg)).
				Foreground(c(colorYellow)).
				Padding(0, 1)

	detailSectionStyle = lipgloss.NewStyle().
				Foreground(c(colorOverlay0)).
				Bold(true)

	detailLabelStyle = lipgloss.NewStyle().
				Foreground(c(colorOverlay1))

	detailValueStyle = lipgloss.NewStyle().
				Foreground(c(colorText))

	detailRevealedStyle = lipgloss.NewStyle().
				Foreground(c(colorGreen)).
				Bold(true)

	otpTimerStyle  = lipgloss.NewStyle().Foreground(c(colorYellow)).Bold(true)
	otpSafeStyle   = lipgloss.NewStyle().Foreground(c(colorGreen))
	otpDangerStyle = lipgloss.NewStyle().Foreground(c(colorRed))

	detailHistoryStyle = lipgloss.NewStyle().
				Foreground(c(colorOverlay0))
)

// ── Overlay / picker ──────────────────────────────────────────────────────────

var (
	overlayStyle = lipgloss.NewStyle().
		Background(c(colorMantle)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(c(colorSurface1)).
		Padding(1, 2)
)

// ── Passgen overlay ───────────────────────────────────────────────────────────

var (
	passGenPanelStyle = lipgloss.NewStyle().
				Background(c(colorBase)).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(c(colorBlue)).
				Padding(1, 2)

	passGenTabActiveStyle = lipgloss.NewStyle().
				Background(c(colorBlue)).
				Foreground(c(colorBase)).
				Bold(true).
				Padding(0, 2)

	passGenTabStyle = lipgloss.NewStyle().
			Background(c(colorSurface0)).
			Foreground(c(colorSubtext0)).
			Padding(0, 2)

	passGenPreviewStyle = lipgloss.NewStyle().
				Background(c(colorSurface0)).
				Border(lipgloss.NormalBorder()).
				BorderForeground(c(colorSurface2)).
				Padding(0, 1).
				Bold(true)

	passGenFocusedStyle = lipgloss.NewStyle().
				Foreground(c(colorBlue)).
				Bold(true)

	passGenLabelStyle = lipgloss.NewStyle().
				Foreground(c(colorSubtext1))

	passGenCheckOnStyle = lipgloss.NewStyle().
				Foreground(c(colorGreen)).
				Bold(true)

	passGenCheckOffStyle = lipgloss.NewStyle().
				Foreground(c(colorOverlay0))

	// Password character colorization
	pwdUpperStyle  = lipgloss.NewStyle().Foreground(c(colorBlue)).Bold(true)
	pwdLowerStyle  = lipgloss.NewStyle().Foreground(c(colorText))
	pwdDigitStyle  = lipgloss.NewStyle().Foreground(c(colorPeach)).Bold(true)
	pwdSymbolStyle = lipgloss.NewStyle().Foreground(c(colorYellow)).Bold(true)
)

// ── Strength ──────────────────────────────────────────────────────────────────

var (
	strengthVeryWeakStyle = lipgloss.NewStyle().Foreground(c(colorRed)).Bold(true)
	strengthWeakStyle     = lipgloss.NewStyle().Foreground(c(colorPeach)).Bold(true)
	strengthFairStyle     = lipgloss.NewStyle().Foreground(c(colorYellow)).Bold(true)
	strengthGoodStyle     = lipgloss.NewStyle().Foreground(c(colorTeal)).Bold(true)
	strengthStrongStyle   = lipgloss.NewStyle().Foreground(c(colorGreen)).Bold(true)
)

// ── Form ─────────────────────────────────────────────────────────────────────

var (
	formLabelStyle = lipgloss.NewStyle().
			Foreground(c(colorSubtext0))

	formLabelActiveStyle = lipgloss.NewStyle().
				Foreground(c(colorBlue)).
				Bold(true)
)

// ── Status / hints ────────────────────────────────────────────────────────────

var (
	statusBarStyle = lipgloss.NewStyle().
			Background(c(colorCrust)).
			Foreground(c(colorSubtext0)).
			Padding(0, 1)

	keyHintStyle = lipgloss.NewStyle().
			Background(c(colorCrust)).
			Foreground(c(colorSubtext0)).
			Padding(0, 1)

	keyStyle = lipgloss.NewStyle().
			Background(c(colorSurface0)).
			Foreground(c(colorBlue)).
			Bold(true).
			Padding(0, 1)

	toastStyle = lipgloss.NewStyle().
			Foreground(c(colorGreen)).
			Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(c(colorRed)).
			Bold(true)

	dimStyle = lipgloss.NewStyle().
			Foreground(c(colorOverlay0))
)
