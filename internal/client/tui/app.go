package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	runewidth "github.com/mattn/go-runewidth"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	commonpb "github.com/efer92/go-yandex-gophkeeper/gen/common"
	vaultpb "github.com/efer92/go-yandex-gophkeeper/gen/vault"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/config"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/grpcclient"
	localvault "github.com/efer92/go-yandex-gophkeeper/internal/client/vault"
)

// ─── View modes ──────────────────────────────────────────────────────────────

type viewMode int

const (
	modeList       viewMode = iota
	modePicker              // "+ Новый" type selector
	modeForm                // create / edit form
	modeDelConf             // delete confirmation
	modeSearch              // inline search
	modePassGen             // password generator overlay
	modeExportPath          // file export path input
)

// ─── Messages ────────────────────────────────────────────────────────────────

type tickMsg time.Time
type loadedMsg []*commonpb.VaultItem
type offlineLoadedMsg struct {
	items    []*commonpb.VaultItem
	cacheAge time.Time
}
type savedMsg struct{}
type deletedMsg struct{}
type toastMsg string
type errMsg error
type clearClipMsg struct{}

// sortMode defines list sort order.
type sortMode int

const (
	sortDefault  sortMode = iota // server order
	sortName                     // A→Z
	sortTypeName                 // type then name
)

// ─── Sidebar ─────────────────────────────────────────────────────────────────

type entryKind int

const (
	kindSection entryKind = iota // не выбирается, только заголовок
	kindItem                     // обычный фильтр / папка
	kindDivider                  // горизонтальный разделитель
)

type catEntry struct {
	kind     entryKind
	icon     string
	label    string
	types    []commonpb.ItemType
	all      bool
	fav      bool
	archived bool
	trashed  bool
	folder   string // имя папки (пустое = не папка)
	sshKey   bool
	isFile   bool
}

// buildSidebar строит полный список записей сайдбара — включая динамические папки.
// Папки выводятся в алфавитном порядке под секцией ПАПКИ.
func (m *Model) buildSidebar() []catEntry {
	entries := []catEntry{
		{kind: kindSection, label: "FILTERS"},
		{kind: kindItem, icon: "🏠", label: "All Items", all: true},
		{kind: kindItem, icon: "⭐", label: "Favorites", fav: true},
		{kind: kindSection, label: "TYPES"},
		{kind: kindItem, icon: "🔑", label: "Login", types: []commonpb.ItemType{commonpb.ItemType_CREDENTIAL, commonpb.ItemType_OTP}},
		{kind: kindItem, icon: "💳", label: "Card", types: []commonpb.ItemType{commonpb.ItemType_CARD}},
		{kind: kindItem, icon: "👤", label: "Identity", types: []commonpb.ItemType{commonpb.ItemType_BINARY}},
		{kind: kindItem, icon: "📄", label: "Note", types: []commonpb.ItemType{commonpb.ItemType_TEXT}},
		{kind: kindItem, icon: "🗝", label: "SSH Keys", sshKey: true},
		{kind: kindItem, icon: "📎", label: "Files", isFile: true},
		{kind: kindSection, label: "FOLDERS"},
	}

	// Собрать уникальные папки из загруженных элементов (сортировка стабильная)
	seen := map[string]bool{}
	var folders []string
	for _, it := range m.items {
		f := getItemFolder(it)
		if f != "" && !seen[f] && !isArchived(it) && !isTrashed(it) {
			seen[f] = true
			folders = append(folders, f)
		}
	}
	// Простая сортировка пузырьком (папок обычно мало)
	for i := 0; i < len(folders); i++ {
		for j := i + 1; j < len(folders); j++ {
			if folders[j] < folders[i] {
				folders[i], folders[j] = folders[j], folders[i]
			}
		}
	}
	for _, f := range folders {
		entries = append(entries, catEntry{kind: kindItem, icon: "📁", label: f, folder: f})
	}

	entries = append(entries,
		catEntry{kind: kindDivider},
		catEntry{kind: kindItem, icon: "🗃", label: "Archive", archived: true},
		catEntry{kind: kindItem, icon: "🗑", label: "Trash", trashed: true},
	)
	return entries
}

// sidebarSelectables возвращает только kindItem из buildSidebar (в порядке catIdx).
func (m *Model) sidebarSelectables() []catEntry {
	var out []catEntry
	for _, e := range m.buildSidebar() {
		if e.kind == kindItem {
			out = append(out, e)
		}
	}
	return out
}

// catCount — количество выбираемых категорий в сайдбаре.
func (m *Model) catCount() int { return len(m.sidebarSelectables()) }

// selectedCat — текущая выбранная категория.
func (m *Model) selectedCat() catEntry {
	sel := m.sidebarSelectables()
	if m.catIdx < 0 || m.catIdx >= len(sel) {
		return sel[0]
	}
	return sel[m.catIdx]
}

// ─── New-item picker ─────────────────────────────────────────────────────────

type pickerEntry struct {
	icon   string
	label  string
	typ    commonpb.ItemType
	isSSH  bool
	isFile bool
}

var pickerEntries = []pickerEntry{
	{"🔑", "Login", commonpb.ItemType_CREDENTIAL, false, false},
	{"💳", "Card", commonpb.ItemType_CARD, false, false},
	{"👤", "Identity", commonpb.ItemType_BINARY, false, false},
	{"📄", "Note", commonpb.ItemType_TEXT, false, false},
	{"🗝", "SSH Key", commonpb.ItemType_TEXT, true, false},
	{"📎", "File", commonpb.ItemType_BINARY, false, true},
}

// ─── Form ────────────────────────────────────────────────────────────────────

type formField struct {
	label    string
	hint     string
	input    textinput.Model
	isSecret bool
	canGen   bool // Ctrl+G generates a random password
}

type itemForm struct {
	typ        commonpb.ItemType
	editItemID string // empty → create
	title      string
	fields     []formField
	focusIdx   int
}

// ─── Model ───────────────────────────────────────────────────────────────────

type Model struct {
	client   *grpcclient.Client
	vaultSvc vaultpb.VaultServiceClient
	cfg      *config.Config

	width, height int
	mode          viewMode
	now           time.Time

	// list
	catIdx  int
	items   []*commonpb.VaultItem
	listIdx int
	loading bool

	// search
	searchQuery string

	// panel focus
	sidebarFocus bool // true = ↑↓ navigate categories; false = ↑↓ navigate items

	// detail
	revealPwd bool

	// toast / error
	toast       string
	toastExpiry time.Time
	lastErr     string

	// picker
	pickerIdx int

	// form
	form *itemForm

	// password generator
	passGen *passGenState

	// delete confirm
	deleteTarget *commonpb.VaultItem

	// export path input
	exportPathInput textinput.Model
	exportItem      *commonpb.VaultItem

	// sort
	sort sortMode

	// sync / offline
	lastSync time.Time
	syncErr  bool      // last sync failed (offline)
	offline  bool      // true = reading from local cache, writes disabled
	cacheAge time.Time // when the local cache was last written
	spinner  int       // 0-7 spinner frame
}

func New(cfg *config.Config) (*Model, error) {
	c, err := grpcclient.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Model{
		client:   c,
		vaultSvc: vaultpb.NewVaultServiceClient(c.Conn()),
		cfg:      cfg,
		now:      time.Now(),
	}, nil
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), m.loadItems())
}

// ─── Update ──────────────────────────────────────────────────────────────────

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

	case tickMsg:
		m.now = time.Time(msg)
		m.spinner = (m.spinner + 1) % 8
		if !m.toastExpiry.IsZero() && m.now.After(m.toastExpiry) {
			m.toast = ""
		}
		return m, tickCmd()

	case clearClipMsg:
		_ = clipboard.WriteAll("")
		m.setToast("Clipboard cleared")

	case loadedMsg:
		m.items = msg
		m.listIdx = 0
		m.loading = false
		m.lastSync = time.Now()
		m.syncErr = false
		m.offline = false
		// Clamp catIdx — число папок могло измениться после сохранения
		if n := m.catCount(); m.catIdx >= n {
			m.catIdx = n - 1
		}

	case offlineLoadedMsg:
		m.items = msg.items
		m.listIdx = 0
		m.loading = false
		m.syncErr = false
		m.offline = true
		m.cacheAge = msg.cacheAge
		if n := m.catCount(); m.catIdx >= n {
			m.catIdx = n - 1
		}

	case savedMsg:
		m.mode = modeList
		m.form = nil
		m.loading = true
		m.setToast("Saved ✓")
		return m, m.loadItems()

	case deletedMsg:
		m.mode = modeList
		m.deleteTarget = nil
		m.loading = true
		m.setToast("Deleted")
		return m, m.loadItems()

	case passGenRefreshMsg:
		if m.passGen != nil {
			m.passGen.preview = string(msg)
		}

	case toastMsg:
		m.setToast(string(msg))

	case errMsg:
		m.lastErr = grpcMsg(msg)
		m.loading = false
		m.syncErr = true
		m.mode = modeList

	case tea.KeyMsg:
		switch m.mode {
		case modeForm:
			return m.handleFormKey(msg)
		case modePicker:
			return m.handlePickerKey(msg)
		case modeDelConf:
			return m.handleDelConfKey(msg)
		case modeSearch:
			return m.handleSearchKey(msg)
		case modeExportPath:
			return m.handleExportPathKey(msg)
		case modePassGen:
			return m.handlePassGenKey(msg)
		default:
			return m.handleListKey(msg)
		}
	}
	return m, nil
}

// ─── List mode keys ──────────────────────────────────────────────────────────

func (m *Model) handleListKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	items := m.filteredItems()
	cat := m.selectedCat()
	n := m.catCount()

	switch msg.String() {
	case "q", "ctrl+c":
		m.client.Close()
		return m, tea.Quit

	// ↑↓ — навигация внутри активной панели
	case "up", "k":
		if m.sidebarFocus {
			if m.catIdx > 0 {
				m.catIdx--
				m.listIdx = 0
				m.revealPwd = false
			}
		} else {
			if m.listIdx > 0 {
				m.listIdx--
				m.revealPwd = false
				m.lastErr = ""
			}
		}
	case "down", "j":
		if m.sidebarFocus {
			if m.catIdx < n-1 {
				m.catIdx++
				m.listIdx = 0
				m.revealPwd = false
			}
		} else {
			if m.listIdx < len(items)-1 {
				m.listIdx++
				m.revealPwd = false
				m.lastErr = ""
			}
		}

	// ← → — переключение фокуса между сайдбаром и списком
	case "left", "h":
		m.sidebarFocus = true
	case "right", "l", "enter":
		if m.sidebarFocus {
			m.sidebarFocus = false
		}

	// Tab — следующая категория (без смены фокуса)
	case "tab":
		m.catIdx = (m.catIdx + 1) % n
		m.listIdx = 0
		m.revealPwd = false
	case "shift+tab":
		m.catIdx = (m.catIdx + n - 1) % n
		m.listIdx = 0
		m.revealPwd = false

	case "n":
		if m.writeBlocked() {
			break
		}
		if !cat.trashed && !cat.archived {
			m.mode = modePicker
			m.pickerIdx = 0
		}
	case "e":
		if m.writeBlocked() {
			break
		}
		if len(items) > 0 && m.listIdx < len(items) && !cat.trashed {
			sel := items[m.listIdx]
			if isFileItem(sel) {
				m.setToast("Use n to re-upload a file")
				break
			}
			if isSSHKey(sel) {
				m.openEditSSHForm(sel)
			} else {
				m.openEditForm(sel)
			}
			return m, textinput.Blink
		}

	case "a": // archive / unarchive
		if m.writeBlocked() {
			break
		}
		if len(items) > 0 && m.listIdx < len(items) {
			item := items[m.listIdx]
			if cat.archived {
				return m, tea.Sequence(m.setItemFlag(item, "archived", false),
					func() tea.Msg { return toastMsg("Unarchived") })
			}
			return m, tea.Sequence(m.setItemFlag(item, "archived", true),
				func() tea.Msg { return toastMsg("Archived") })
		}

	case "d": // move to trash / delete permanently
		if m.writeBlocked() {
			break
		}
		if len(items) > 0 && m.listIdx < len(items) {
			item := items[m.listIdx]
			if cat.trashed {
				m.deleteTarget = item
				m.mode = modeDelConf
			} else {
				return m, tea.Sequence(m.setItemFlag(item, "trashed", true),
					func() tea.Msg { return toastMsg("Moved to Trash") })
			}
		}

	case "f": // add/remove favorite
		if m.writeBlocked() {
			break
		}
		if len(items) > 0 && m.listIdx < len(items) {
			item := items[m.listIdx]
			newVal := !isFavorite(item)
			msg := "Added to Favorites ⭐"
			if !newVal {
				msg = "Removed from Favorites"
			}
			return m, tea.Sequence(m.setItemFlag(item, "favorite", newVal),
				func() tea.Msg { return toastMsg(msg) })
		}

	case "R": // restore from trash / archive
		if m.writeBlocked() {
			break
		}
		if len(items) > 0 && m.listIdx < len(items) {
			item := items[m.listIdx]
			if cat.trashed {
				return m, tea.Sequence(m.setItemFlag(item, "trashed", false),
					func() tea.Msg { return toastMsg("Restored") })
			} else if cat.archived {
				return m, tea.Sequence(m.setItemFlag(item, "archived", false),
					func() tea.Msg { return toastMsg("Unarchived") })
			}
		}

	case "c":
		return m, m.copyField(items, "password")
	case "u":
		return m, m.copyField(items, "username")
	case "t":
		return m, m.copyField(items, "totp")
	case "x":
		if len(items) > 0 && m.listIdx < len(items) && isFileItem(items[m.listIdx]) {
			m.openExportPath(items[m.listIdx])
			return m, nil
		}
	case "p":
		m.revealPwd = !m.revealPwd
	case "r":
		m.loading = true
		m.syncErr = false
		m.offline = false
		return m, m.loadItems()
	case "/":
		m.mode = modeSearch
		m.searchQuery = ""
	case "g":
		m.passGen = newPassGenState(-1)
		m.mode = modePassGen
	case "S":
		m.sort = (m.sort + 1) % 3
		m.listIdx = 0
	case "o":
		if len(items) > 0 && m.listIdx < len(items) {
			p := parseLoginPayload(items[m.listIdx].GetPayload(), "")
			if p.URL != "" {
				openURL(p.URL)
			}
		}
	case "D":
		if len(items) > 0 && m.listIdx < len(items) {
			return m, m.duplicateItem(items[m.listIdx])
		}
	}
	return m, nil
}

// ─── Picker mode keys ────────────────────────────────────────────────────────

func (m *Model) handlePickerKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = modeList
	case "up", "k":
		if m.pickerIdx > 0 {
			m.pickerIdx--
		}
	case "down", "j":
		if m.pickerIdx < len(pickerEntries)-1 {
			m.pickerIdx++
		}
	case "1", "2", "3", "4", "5", "6":
		idx := int(msg.Runes[0] - '1')
		if idx < len(pickerEntries) {
			m.pickerIdx = idx
			e := pickerEntries[idx]
			switch {
			case e.isSSH:
				m.openNewSSHForm()
			case e.isFile:
				m.openNewFileForm()
			default:
				m.openNewForm(e.typ)
			}
			return m, textinput.Blink
		}
	case "enter":
		e := pickerEntries[m.pickerIdx]
		switch {
		case e.isSSH:
			m.openNewSSHForm()
		case e.isFile:
			m.openNewFileForm()
		default:
			m.openNewForm(e.typ)
		}
		return m, textinput.Blink
	}
	return m, nil
}

// ─── Delete confirm mode keys ─────────────────────────────────────────────────

func (m *Model) handleDelConfKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		target := m.deleteTarget
		return m, func() (msg tea.Msg) {
			defer func() {
				if r := recover(); r != nil {
					msg = errMsg(fmt.Errorf("сервер недоступен"))
				}
			}()
			ctx, cancel := m.grpcCtx()
			defer cancel()
			_, err := m.vaultSvc.DeleteItem(ctx, vaultpb.DeleteItemRequest_builder{Id: target.GetId()}.Build())
			if err != nil {
				return errMsg(err)
			}
			return deletedMsg{}
		}
	default:
		m.mode = modeList
		m.deleteTarget = nil
	}
	return m, nil
}

// ─── Search mode keys ─────────────────────────────────────────────────────────

func (m *Model) handleSearchKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = modeList
		m.searchQuery = ""
	case "enter":
		m.mode = modeList
	case "backspace":
		if len(m.searchQuery) > 0 {
			runes := []rune(m.searchQuery)
			m.searchQuery = string(runes[:len(runes)-1])
		}
	default:
		if len(msg.Runes) > 0 {
			m.searchQuery += string(msg.Runes)
		}
	}
	return m, nil
}

// ─── Form mode keys ──────────────────────────────────────────────────────────

func (m *Model) handleFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := m.form
	switch msg.String() {
	case "esc":
		m.mode = modeList
		m.form = nil
		return m, nil
	case "ctrl+g":
		if f.fields[f.focusIdx].canGen {
			m.passGen = newPassGenState(f.focusIdx)
			m.mode = modePassGen
		}
		return m, nil
	case "ctrl+s":
		return m, m.saveForm()
	case "tab", "down":
		f.fields[f.focusIdx].input.Blur()
		f.focusIdx = (f.focusIdx + 1) % len(f.fields)
		f.fields[f.focusIdx].input.Focus()
		return m, textinput.Blink
	case "shift+tab", "up":
		f.fields[f.focusIdx].input.Blur()
		f.focusIdx = (f.focusIdx + len(f.fields) - 1) % len(f.fields)
		f.fields[f.focusIdx].input.Focus()
		return m, textinput.Blink
	case "enter":
		if f.focusIdx < len(f.fields)-1 {
			f.fields[f.focusIdx].input.Blur()
			f.focusIdx++
			f.fields[f.focusIdx].input.Focus()
			return m, textinput.Blink
		}
		return m, m.saveForm()
	default:
		var cmd tea.Cmd
		f.fields[f.focusIdx].input, cmd = f.fields[f.focusIdx].input.Update(msg)
		return m, cmd
	}
}

// ─── Form builders ───────────────────────────────────────────────────────────

func mkInput(placeholder, value string, width int) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.Width = width
	if value != "" {
		ti.SetValue(value)
	}
	return ti
}

func mkSecret(placeholder, value string, width int) textinput.Model {
	ti := mkInput(placeholder, value, width)
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	return ti
}

func (m *Model) openNewForm(typ commonpb.ItemType) {
	// Если выбрана папка в сайдбаре — предзаполнить её
	preFolder := m.selectedCat().folder
	m.form = m.buildForm(typ, "", nil, preFolder)
	m.form.fields[0].input.Focus()
	m.mode = modeForm
	m.lastErr = ""
}

func (m *Model) openEditForm(item *commonpb.VaultItem) {
	m.form = m.buildForm(item.GetType(), item.GetId(), item, "")
	m.form.fields[0].input.Focus()
	m.mode = modeForm
	m.lastErr = ""
}

func (m *Model) openNewSSHForm() {
	const w = 44
	m.form = &itemForm{
		typ:   commonpb.ItemType_TEXT,
		title: "SSH Key",
		fields: []formField{
			{label: "Name *", input: mkInput("id_ed25519 (server)", "", w)},
			{label: "Key Type", input: mkInput("ed25519", "ed25519", w), hint: "ed25519, rsa, ecdsa"},
			{label: "Private Key (PEM)", input: mkInput("-----BEGIN OPENSSH PRIVATE KEY-----", "", w), hint: "Paste .pem file content"},
			{label: "Public Key", input: mkInput("ssh-ed25519 AAAA...", "", w)},
			{label: "Comment", input: mkInput("work server", "", w)},
			{label: "Folder", input: mkInput("", "", w)},
		},
		focusIdx: 0,
	}
	m.form.fields[0].input.Focus()
	m.mode = modeForm
	m.lastErr = ""
}

func (m *Model) openEditSSHForm(item *commonpb.VaultItem) {
	const w = 44
	p := parseSSHKeyPayload(item.GetPayload(), item.GetMetadata())
	folder := getItemFolder(item)
	m.form = &itemForm{
		typ:        commonpb.ItemType_TEXT,
		editItemID: item.GetId(),
		title:      "SSH Key",
		fields: []formField{
			{label: "Name *", input: mkInput("id_ed25519", p.Name, w)},
			{label: "Key Type", input: mkInput("ed25519", p.KeyType, w)},
			{label: "Private Key (PEM)", input: mkInput("-----BEGIN...", p.PrivateKey, w)},
			{label: "Public Key", input: mkInput("ssh-ed25519 AAAA...", p.PublicKey, w)},
			{label: "Comment", input: mkInput("", p.Comment, w)},
			{label: "Folder", input: mkInput("", folder, w)},
		},
		focusIdx: 0,
	}
	m.form.fields[0].input.Focus()
	m.mode = modeForm
	m.lastErr = ""
}

func (m *Model) openNewFileForm() {
	const w = 60
	m.form = &itemForm{
		typ:   commonpb.ItemType_BINARY,
		title: "File",
		fields: []formField{
			{label: "Display Name *", input: mkInput("document.pdf", "", w)},
			{label: "File Path", input: mkInput("/path/to/file.pdf", "", w), hint: "Absolute or relative path to the file"},
			{label: "Folder", input: mkInput("", "", w)},
		},
		focusIdx: 0,
	}
	m.form.fields[0].input.Focus()
	m.mode = modeForm
	m.lastErr = ""
}

// existingFolders возвращает список уникальных папок для подсказки в форме.
func (m *Model) existingFolders() []string {
	seen := map[string]bool{}
	var out []string
	for _, it := range m.items {
		if f := getItemFolder(it); f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

func (m *Model) buildForm(typ commonpb.ItemType, editID string, item *commonpb.VaultItem, preFolder string) *itemForm {
	const w = 44
	meta := ""
	if item != nil {
		meta = item.GetMetadata()
	}

	// Текущая папка элемента (для редактирования) или предзаполненная (для создания)
	currentFolder := preFolder
	if item != nil {
		currentFolder = getItemFolder(item)
	}

	// Подсказка: показать существующие папки
	folderHint := ""
	if folders := m.existingFolders(); len(folders) > 0 {
		folderHint = "Existing: " + strings.Join(folders, ", ")
	}
	folderField := formField{
		label: "Folder",
		input: mkInput("e.g. Work", currentFolder, w),
		hint:  folderHint,
	}

	var title string
	var fields []formField

	switch typ {
	case commonpb.ItemType_CREDENTIAL:
		title = "Login"
		p := LoginPayload{}
		if item != nil {
			p = parseLoginPayload(item.GetPayload(), meta)
		}
		fields = []formField{
			{label: "Name *", input: mkInput("github.com", p.Name, w)},
			{label: "Username", input: mkInput("user1", p.Username, w)},
			{label: "Password", input: mkSecret("••••••••", p.Password, w), isSecret: true, canGen: true},
			{label: "Website", input: mkInput("https://", p.URL, w)},
			{label: "Authenticator Key (TOTP)", input: mkInput("", p.TOTPKey, w)},
			{label: "Notes", input: mkInput("", p.Notes, w)},
			folderField,
		}

	case commonpb.ItemType_CARD:
		title = "Card"
		p := CardPayload{}
		if item != nil {
			p = parseCardPayload(item.GetPayload(), meta)
		}
		fields = []formField{
			{label: "Name *", input: mkInput("Visa Gold", p.Name, w)},
			{label: "Cardholder", input: mkInput("John Doe", p.CardholderName, w)},
			{label: "Card Number", input: mkSecret("1234 5678 9012 3456", p.Number, w), isSecret: true},
			{label: "Month (MM)", input: mkInput("12", p.ExpMonth, 6)},
			{label: "Year (YYYY)", input: mkInput("2028", p.ExpYear, 8)},
			{label: "CVV", input: mkSecret("•••", p.CVV, 6), isSecret: true},
			{label: "Notes", input: mkInput("", p.Notes, w)},
			folderField,
		}

	case commonpb.ItemType_TEXT:
		title = "Note"
		p := NotePayload{}
		if item != nil {
			p = parseNotePayload(item.GetPayload(), meta)
		}
		fields = []formField{
			{label: "Name *", input: mkInput("API Keys", p.Name, w)},
			{label: "Content", input: mkInput("", p.Content, w)},
			folderField,
		}

	case commonpb.ItemType_BINARY:
		title = "Identity"
		p := IdentityPayload{}
		if item != nil {
			p = parseIdentityPayload(item.GetPayload(), meta)
		}
		fields = []formField{
			{label: "Name *", input: mkInput("My Profile", p.Name, w)},
			{label: "First Name", input: mkInput("John", p.FirstName, w)},
			{label: "Last Name", input: mkInput("Doe", p.LastName, w)},
			{label: "Email", input: mkInput("user1@example.com", p.Email, w)},
			{label: "Phone", input: mkInput("+1 555 000 0000", p.Phone, w)},
			{label: "Company", input: mkInput("", p.Company, w)},
			{label: "Address", input: mkInput("", p.Address, w)},
			{label: "Notes", input: mkInput("", p.Notes, w)},
			folderField,
		}

	case commonpb.ItemType_OTP:
		title = "Authenticator"
		p := AuthPayload{}
		if item != nil {
			p = parseAuthPayload(item.GetPayload(), meta)
		}
		fields = []formField{
			{label: "Name *", input: mkInput("GitHub 2FA", p.Name, w)},
			{label: "Secret (base32)", input: mkInput("", p.Secret, w)},
			{label: "Issuer", input: mkInput("GitHub", p.Issuer, w)},
			folderField,
		}
	}

	return &itemForm{typ: typ, editItemID: editID, title: title, fields: fields}
}

// ─── Save form ───────────────────────────────────────────────────────────────

func (m *Model) saveForm() tea.Cmd {
	form := m.form
	vals := make([]string, len(form.fields))
	for i, f := range form.fields {
		vals[i] = strings.TrimSpace(f.input.Value())
	}
	if vals[0] == "" {
		m.lastErr = "Name is required"
		return nil
	}

	// Папка — всегда последнее поле формы
	folder := vals[len(vals)-1]

	return func() (msg tea.Msg) {
		defer func() {
			if r := recover(); r != nil {
				msg = errMsg(fmt.Errorf("сервер недоступен"))
			}
		}()
		var payload []byte
		meta := vals[0]

		// File attachment form
		if form.title == "File" {
			filePath := strings.TrimSpace(vals[1])
			fileFolder := vals[len(vals)-1]
			fileData, err := os.ReadFile(filePath)
			if err != nil {
				return errMsg(fmt.Errorf("cannot read file: %w", err))
			}
			const maxFileSize = 10 << 20 // 10 MB
			if len(fileData) > maxFileSize {
				return errMsg(fmt.Errorf("file too large: max 10 MB, got %s", FormatFileSize(int64(len(fileData)))))
			}
			mimeType := http.DetectContentType(fileData)
			p := FilePayload{
				Name:     vals[0],
				FileName: filepath.Base(filePath),
				MimeType: mimeType,
				Size:     int64(len(fileData)),
				Data:     fileData,
				IsFile:   true,
			}
			payload, _ = json.Marshal(p)
			if fileFolder != "" {
				var data map[string]interface{}
				if json.Unmarshal(payload, &data) == nil {
					data["folder"] = fileFolder
					if patched, err2 := json.Marshal(data); err2 == nil {
						payload = patched
					}
				}
			}
			ctx, cancel := m.grpcCtx()
			defer cancel()
			if form.editItemID == "" {
				_, err = m.vaultSvc.CreateItem(ctx, vaultpb.CreateItemRequest_builder{
					Type:     form.typ,
					Payload:  payload,
					Metadata: meta,
				}.Build())
			} else {
				_, err = m.vaultSvc.UpdateItem(ctx, vaultpb.UpdateItemRequest_builder{
					Id:       form.editItemID,
					Payload:  payload,
					Metadata: meta,
				}.Build())
			}
			if err != nil {
				return errMsg(err)
			}
			return savedMsg{}
		}

		// SSH key form
		if form.title == "SSH Key" {
			folder := vals[len(vals)-1]
			p := SSHKeyPayload{
				Name:       vals[0],
				KeyType:    vals[1],
				PrivateKey: vals[2],
				PublicKey:  vals[3],
				Comment:    vals[4],
				SSHKey:     true,
			}
			payload, _ = json.Marshal(p)
			if folder != "" {
				var data map[string]interface{}
				if json.Unmarshal(payload, &data) == nil {
					data["folder"] = folder
					if patched, err := json.Marshal(data); err == nil {
						payload = patched
					}
				}
			}
			ctx, cancel := m.grpcCtx()
			defer cancel()
			var err error
			if form.editItemID == "" {
				_, err = m.vaultSvc.CreateItem(ctx, vaultpb.CreateItemRequest_builder{
					Type:     form.typ,
					Payload:  payload,
					Metadata: meta,
				}.Build())
			} else {
				_, err = m.vaultSvc.UpdateItem(ctx, vaultpb.UpdateItemRequest_builder{
					Id:       form.editItemID,
					Payload:  payload,
					Metadata: meta,
				}.Build())
			}
			if err != nil {
				return errMsg(err)
			}
			return savedMsg{}
		}

		switch form.typ {
		case commonpb.ItemType_CREDENTIAL:
			newPwd := vals[2]
			var history []PasswordHistoryEntry
			if form.editItemID != "" {
				// Carry over existing history; prepend old password if it changed.
				for _, it := range m.items {
					if it.GetId() == form.editItemID {
						old := parseLoginPayload(it.GetPayload(), it.GetMetadata())
						history = old.History
						if old.Password != "" && old.Password != newPwd {
							entry := PasswordHistoryEntry{Password: old.Password, LastUsed: time.Now()}
							history = append([]PasswordHistoryEntry{entry}, history...)
							if len(history) > 10 {
								history = history[:10]
							}
						}
						break
					}
				}
			}
			payload, _ = json.Marshal(LoginPayload{
				Name:     vals[0],
				Username: vals[1],
				Password: newPwd,
				URL:      vals[3],
				TOTPKey:  vals[4],
				Notes:    vals[5],
				History:  history,
			})
		case commonpb.ItemType_CARD:
			payload, _ = json.Marshal(CardPayload{
				Name:           vals[0],
				CardholderName: vals[1],
				Number:         vals[2],
				ExpMonth:       vals[3],
				ExpYear:        vals[4],
				CVV:            vals[5],
				Notes:          vals[6],
			})
		case commonpb.ItemType_TEXT:
			payload, _ = json.Marshal(NotePayload{Name: vals[0], Content: vals[1]})
		case commonpb.ItemType_BINARY:
			payload, _ = json.Marshal(IdentityPayload{
				Name:      vals[0],
				FirstName: vals[1],
				LastName:  vals[2],
				Email:     vals[3],
				Phone:     vals[4],
				Company:   vals[5],
				Address:   vals[6],
				Notes:     vals[7],
			})
		case commonpb.ItemType_OTP:
			payload, _ = json.Marshal(AuthPayload{Name: vals[0], Secret: vals[1], Issuer: vals[2]})
		}

		// Добавить папку в payload (patch через map, чтобы не трогать типы)
		if folder != "" {
			var data map[string]interface{}
			if json.Unmarshal(payload, &data) == nil {
				data["folder"] = folder
				if patched, err := json.Marshal(data); err == nil {
					payload = patched
				}
			}
		}

		ctx, cancel := m.grpcCtx()
		defer cancel()
		var err error
		if form.editItemID == "" {
			_, err = m.vaultSvc.CreateItem(ctx, vaultpb.CreateItemRequest_builder{
				Type:     form.typ,
				Payload:  payload,
				Metadata: meta,
			}.Build())
		} else {
			_, err = m.vaultSvc.UpdateItem(ctx, vaultpb.UpdateItemRequest_builder{
				Id:       form.editItemID,
				Payload:  payload,
				Metadata: meta,
			}.Build())
		}
		if err != nil {
			return errMsg(err)
		}
		return savedMsg{}
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func (m *Model) filteredItems() []*commonpb.VaultItem {
	cat := m.selectedCat()
	var base []*commonpb.VaultItem
	for _, item := range m.items {
		arch := isArchived(item)
		trash := isTrashed(item)

		// Special views: show only their flag, not both
		if cat.trashed {
			if trash {
				base = append(base, item)
			}
			continue
		}
		if cat.archived {
			if arch && !trash {
				base = append(base, item)
			}
			continue
		}

		// Normal views: exclude archived and trashed
		if arch || trash {
			continue
		}

		if cat.sshKey {
			if isSSHKey(item) {
				base = append(base, item)
			}
			continue
		}
		if cat.isFile {
			if isFileItem(item) {
				base = append(base, item)
			}
			continue
		}
		if cat.folder != "" {
			if getItemFolder(item) == cat.folder {
				base = append(base, item)
			}
		} else if cat.all {
			base = append(base, item)
		} else if cat.fav {
			if isFavorite(item) {
				base = append(base, item)
			}
		} else {
			for _, t := range cat.types {
				if item.GetType() == t {
					// Exclude file attachments from Identity filter
					if t == commonpb.ItemType_BINARY && isFileItem(item) {
						break
					}
					base = append(base, item)
					break
				}
			}
		}
	}
	if m.searchQuery != "" {
		q := strings.ToLower(m.searchQuery)
		var filtered []*commonpb.VaultItem
		for _, item := range base {
			if strings.Contains(strings.ToLower(item.GetMetadata()), q) {
				filtered = append(filtered, item)
			}
		}
		base = filtered
	}

	// Apply sort
	switch m.sort {
	case sortName:
		for i := 0; i < len(base); i++ {
			for j := i + 1; j < len(base); j++ {
				if strings.ToLower(base[j].GetMetadata()) < strings.ToLower(base[i].GetMetadata()) {
					base[i], base[j] = base[j], base[i]
				}
			}
		}
	case sortTypeName:
		for i := 0; i < len(base); i++ {
			for j := i + 1; j < len(base); j++ {
				ti, tj := int(base[i].GetType()), int(base[j].GetType())
				if tj < ti || (tj == ti && strings.ToLower(base[j].GetMetadata()) < strings.ToLower(base[i].GetMetadata())) {
					base[i], base[j] = base[j], base[i]
				}
			}
		}
	}
	return base
}

func getItemFolder(item *commonpb.VaultItem) string {
	var f struct {
		Folder string `json:"folder"`
	}
	_ = json.Unmarshal(item.GetPayload(), &f)
	return f.Folder
}

func isFavorite(item *commonpb.VaultItem) bool {
	var f struct {
		Favorite bool `json:"favorite"`
	}
	_ = json.Unmarshal(item.GetPayload(), &f)
	return f.Favorite
}

func isArchived(item *commonpb.VaultItem) bool {
	var f struct {
		Archived bool `json:"archived"`
	}
	_ = json.Unmarshal(item.GetPayload(), &f)
	return f.Archived
}

func isTrashed(item *commonpb.VaultItem) bool {
	var f struct {
		Trashed bool `json:"trashed"`
	}
	_ = json.Unmarshal(item.GetPayload(), &f)
	return f.Trashed
}

func isSSHKey(item *commonpb.VaultItem) bool {
	if item.GetType() != commonpb.ItemType_TEXT {
		return false
	}
	var f struct {
		SSHKey bool `json:"ssh_key"`
	}
	_ = json.Unmarshal(item.GetPayload(), &f)
	return f.SSHKey
}

func isFileItem(item *commonpb.VaultItem) bool {
	if item.GetType() != commonpb.ItemType_BINARY {
		return false
	}
	var f struct {
		IsFile bool `json:"is_file"`
	}
	_ = json.Unmarshal(item.GetPayload(), &f)
	return f.IsFile
}

// setItemFlag patches a bool flag in the item's JSON payload and calls UpdateItem.
func (m *Model) setItemFlag(item *commonpb.VaultItem, flag string, value bool) tea.Cmd {
	return func() (msg tea.Msg) {
		defer func() {
			if r := recover(); r != nil {
				msg = errMsg(fmt.Errorf("сервер недоступен"))
			}
		}()
		var data map[string]interface{}
		if err := json.Unmarshal(item.GetPayload(), &data); err != nil {
			data = make(map[string]interface{})
		}
		if value {
			data[flag] = true
		} else {
			delete(data, flag)
		}
		newPayload, err := json.Marshal(data)
		if err != nil {
			return errMsg(err)
		}
		ctx, cancel := m.grpcCtx()
		defer cancel()
		_, err = m.vaultSvc.UpdateItem(ctx, vaultpb.UpdateItemRequest_builder{
			Id:       item.GetId(),
			Payload:  newPayload,
			Metadata: item.GetMetadata(),
		}.Build())
		if err != nil {
			return errMsg(err)
		}
		return savedMsg{}
	}
}

// grpcCtx returns a context with a 10-second deadline, already decorated with the
// auth token. The caller must defer cancel() to free resources.
func (m *Model) grpcCtx() (context.Context, context.CancelFunc) {
	return m.grpcCtxTimeout(10 * time.Second)
}

// grpcCtxTimeout returns a context with the given deadline, decorated with the auth token.
func (m *Model) grpcCtxTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	return m.client.WithAuth(ctx), cancel
}

// writeBlocked returns true and shows a "Read Only Mode" toast when the TUI is in
// offline mode and a write-mutating key was pressed.
func (m *Model) writeBlocked() bool {
	if m.offline {
		m.setToast("Read Only Mode")
		return true
	}
	return false
}

func (m *Model) loadItems() tea.Cmd {
	cfg := m.cfg
	grpcClient := m.client
	vaultSvc := m.vaultSvc
	return func() (msg tea.Msg) {
		defer func() {
			if r := recover(); r != nil {
				msg = tryLoadCache(cfg)
			}
		}()
		ctx, cancel := context.WithTimeout(grpcClient.WithAuth(context.Background()), 5*time.Second)
		defer cancel()
		resp, err := vaultSvc.ListItems(ctx, vaultpb.ListItemsRequest_builder{Limit: 1000}.Build())
		if err != nil {
			return tryLoadCache(cfg)
		}
		// Online: persist to local cache for offline use.
		if cfg.RefreshToken != "" && cfg.VaultPath != "" {
			key := localvault.CacheKey(cfg.RefreshToken)
			_ = localvault.Save(cfg.VaultPath, key, resp.GetItems())
		}
		return loadedMsg(resp.GetItems())
	}
}

// errServerUnavailable is shown in the TUI when neither the server nor the local cache is reachable.
var errServerUnavailable = errors.New("server unavailable")

// tryLoadCache attempts to read the local encrypted vault cache.
// Returns offlineLoadedMsg on success or errMsg if no cache is available.
func tryLoadCache(cfg *config.Config) tea.Msg {
	if cfg.RefreshToken == "" || cfg.VaultPath == "" {
		return errMsg(errServerUnavailable)
	}
	key := localvault.CacheKey(cfg.RefreshToken)
	items, age, err := localvault.Load(cfg.VaultPath, key)
	if err != nil {
		return errMsg(errServerUnavailable)
	}
	return offlineLoadedMsg{items: items, cacheAge: age}
}

func (m *Model) copyField(items []*commonpb.VaultItem, field string) tea.Cmd {
	if len(items) == 0 || m.listIdx >= len(items) {
		return nil
	}
	item := items[m.listIdx]
	var text string
	switch field {
	case "password":
		p := parseLoginPayload(item.GetPayload(), item.GetMetadata())
		text = p.Password
		// also handle card CVV
		if text == "" {
			cp := parseCardPayload(item.GetPayload(), item.GetMetadata())
			text = cp.CVV
		}
	case "username":
		p := parseLoginPayload(item.GetPayload(), item.GetMetadata())
		text = p.Username
	case "totp":
		// login with embedded TOTP
		lp := parseLoginPayload(item.GetPayload(), item.GetMetadata())
		if lp.TOTPKey != "" {
			text = m.generateTOTP(lp.TOTPKey)
		} else {
			ap := parseAuthPayload(item.GetPayload(), item.GetMetadata())
			text = m.generateTOTP(ap.Secret)
		}
	}
	if text == "" {
		return nil
	}
	_ = clipboard.WriteAll(text)
	return tea.Batch(
		func() tea.Msg { return toastMsg("Copied ✓  (clears in 30s)") },
		tea.Tick(30*time.Second, func(t time.Time) tea.Msg { return clearClipMsg{} }),
	)
}

func (m *Model) exportFile(item *commonpb.VaultItem) tea.Cmd {
	return func() (msg tea.Msg) {
		defer func() {
			if r := recover(); r != nil {
				msg = errMsg(fmt.Errorf("export failed"))
			}
		}()
		p := parseFilePayload(item.GetPayload(), item.GetMetadata())
		if len(p.Data) == 0 {
			return errMsg(fmt.Errorf("no file data"))
		}
		outPath := m.exportPathInput.Value()
		if outPath == "" {
			outPath = p.FileName
		}
		// Expand ~ to home directory.
		if strings.HasPrefix(outPath, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				outPath = filepath.Join(home, outPath[2:])
			}
		}
		if err := os.WriteFile(outPath, p.Data, 0o600); err != nil {
			return errMsg(fmt.Errorf("export: %w", err))
		}
		return toastMsg(fmt.Sprintf("Saved → %s (%s)", outPath, FormatFileSize(p.Size)))
	}
}

func (m *Model) openExportPath(item *commonpb.VaultItem) {
	p := parseFilePayload(item.GetPayload(), item.GetMetadata())
	home, _ := os.UserHomeDir()
	defaultPath := filepath.Join(home, "Downloads", p.FileName)

	ti := textinput.New()
	ti.SetValue(defaultPath)
	ti.Focus()
	inputW := m.width - 20
	if inputW < 30 {
		inputW = 30
	}
	if inputW > 60 {
		inputW = 60
	}
	ti.Width = inputW

	m.exportPathInput = ti
	m.exportItem = item
	m.mode = modeExportPath
}

func (m *Model) handleExportPathKey(msg tea.KeyMsg) (*Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.mode = modeList
		m.exportItem = nil
		return m, nil
	case tea.KeyEnter:
		item := m.exportItem
		m.mode = modeList
		m.exportItem = nil
		return m, m.exportFile(item)
	}
	var cmd tea.Cmd
	m.exportPathInput, cmd = m.exportPathInput.Update(msg)
	return m, cmd
}

func (m *Model) viewExportPath() string {
	var sb strings.Builder
	sb.WriteString(lipgloss.NewStyle().Foreground(c(colorMauve)).Bold(true).Render("Export File") + "\n\n")
	sb.WriteString(dimStyle.Render("Save to:") + "\n")
	sb.WriteString(m.exportPathInput.View() + "\n\n")
	sb.WriteString(dimStyle.Render("Enter — save   Esc — cancel"))
	return overlayStyle.Render(sb.String())
}

func (m *Model) generateTOTP(secret string) string {
	if secret == "" {
		return ""
	}
	code, err := totp.GenerateCodeCustom(secret, m.now, totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return "------"
	}
	return code
}

func (m *Model) duplicateItem(item *commonpb.VaultItem) tea.Cmd {
	return func() (msg tea.Msg) {
		defer func() {
			if r := recover(); r != nil {
				msg = errMsg(fmt.Errorf("сервер недоступен"))
			}
		}()
		ctx, cancel := m.grpcCtx()
		defer cancel()
		_, err := m.vaultSvc.CreateItem(ctx, vaultpb.CreateItemRequest_builder{
			Type:     item.GetType(),
			Payload:  item.GetPayload(),
			Metadata: item.GetMetadata() + " (копия)",
		}.Build())
		if err != nil {
			return errMsg(err)
		}
		return savedMsg{}
	}
}

func (m *Model) setToast(s string) {
	m.toast = s
	m.toastExpiry = time.Now().Add(3 * time.Second)
}

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"}

func (m *Model) renderHeader() string {
	left := " GophKeeper  |  " + m.cfg.Username

	var right string
	if m.loading {
		right = spinFrames[m.spinner] + " Syncing..."
	} else if m.offline {
		age := ""
		if !m.cacheAge.IsZero() {
			age = " (cache " + m.cacheAge.Format("02 Jan 15:04") + ")"
		}
		right = errorStyle.Render("Server Status: Offline — Read Only Mode" + age + "  r retry")
	} else if m.syncErr {
		right = errorStyle.Render("⚠ Server unavailable  —  r to retry")
	} else if !m.lastSync.IsZero() {
		ago := time.Since(m.lastSync).Round(time.Second)
		var agoStr string
		switch {
		case ago < time.Minute:
			agoStr = fmt.Sprintf("%ds ago", int(ago.Seconds()))
		case ago < time.Hour:
			agoStr = fmt.Sprintf("%dm ago", int(ago.Minutes()))
		default:
			agoStr = m.lastSync.Format("15:04")
		}
		right = dimStyle.Render("✓ synced " + agoStr + "  r refresh")
	}

	// sort indicator
	sortLabel := ""
	switch m.sort {
	case sortName:
		sortLabel = dimStyle.Render("  [A→Z]")
	case sortTypeName:
		sortLabel = dimStyle.Render("  [type]")
	}

	pad := m.width - len([]rune(left)) - lipgloss.Width(right) - lipgloss.Width(sortLabel) - 2
	if pad < 1 {
		pad = 1
	}
	return left + strings.Repeat(" ", pad) + right + sortLabel
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// ─── View ─────────────────────────────────────────────────────────────────────

func (m *Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}
	switch m.mode {
	case modeForm:
		return m.viewForm()
	case modePicker:
		return m.viewWithOverlay(m.viewPicker())
	case modeDelConf:
		return m.viewWithOverlay(m.viewDeleteConfirm())
	case modeExportPath:
		return m.viewWithOverlay(m.viewExportPath())
	case modePassGen:
		if m.passGen != nil {
			return m.viewWithOverlay(m.viewPassGen())
		}
		return m.viewList()
	default:
		return m.viewList()
	}
}

func (m *Model) viewList() string {
	const sbW = 36
	detW := 60
	switch {
	case m.width >= 200:
		detW = 72
	case m.width >= 160:
		detW = 60
	case m.width >= 130:
		detW = 50
	case m.width >= 100:
		detW = 42
	case m.width < 90:
		detW = 0
	}
	listW := m.width - sbW - detW - 2 // -2 for borders
	if listW < 10 {
		listW = 10
	}
	bodyH := m.height - 2 // header(1) + status(1)
	if bodyH < 1 {
		bodyH = 1
	}

	sidebar := m.renderSidebar(sbW, bodyH)
	list := m.renderList(listW, bodyH)
	detail := m.renderDetail(detW, bodyH)
	status := m.renderStatus()

	header := headerStyle.Width(m.width).Render(m.renderHeader())
	body := lipgloss.JoinHorizontal(lipgloss.Top, sidebar, list, detail)
	return lipgloss.JoinVertical(lipgloss.Left, header, body, status)
}

// ─── Sidebar ─────────────────────────────────────────────────────────────────

func (m *Model) renderSidebar(w, h int) string {
	const sbInner = 28 // ширина текста внутри сайдбара
	var sb strings.Builder
	selPos := 0

	prevKind := kindSection
	for _, e := range m.buildSidebar() {
		switch e.kind {
		case kindSection:
			// пустая строка перед каждой секцией кроме первой
			if prevKind != kindSection {
				sb.WriteString("\n")
			}
			sb.WriteString(sidebarSectionStyle.Render(e.label) + "\n")
			prevKind = kindSection
			continue
		case kindDivider:
			sb.WriteString("\n" + sidebarDividerStyle.Render(strings.Repeat("─", sbInner)) + "\n\n")
			prevKind = kindDivider
			continue
		}

		isCurrent := selPos == m.catIdx

		// Левый индикатор ▌ (2 символа)
		var indicator string
		if isCurrent {
			if m.sidebarFocus {
				indicator = sidebarIndicatorFocused.Render("▌")
			} else {
				indicator = sidebarIndicatorBlur.Render("▌")
			}
		} else {
			indicator = sidebarItemStyle.Render(" ")
		}

		// Эмодзи = 2 колонки; добиваем до 3, остаток — текст метки.
		iconW := lipgloss.Width(e.icon)
		iconPad := strings.Repeat(" ", max(0, 3-iconW))
		label := e.icon + iconPad + truncate(e.label, sbInner-3)

		rowStyle := sidebarItemStyle
		if isCurrent {
			if m.sidebarFocus {
				rowStyle = sidebarSelectedStyle
			} else {
				rowStyle = sidebarActiveStyle
			}
		}
		rowRendered := rowStyle.Width(sbInner).Render(label)

		sb.WriteString(indicator + rowRendered + "\n")
		prevKind = kindItem
		selPos++
	}

	// ── Server Status footer ──────────────────────────────────────────────────
	sb.WriteString("\n" + sidebarDividerStyle.Render(strings.Repeat("─", sbInner)) + "\n")
	var statusLine string
	if m.syncErr || m.offline {
		statusLine = sidebarItemStyle.Render("🔴 Server Status: Offline")
	} else {
		statusLine = sidebarItemStyle.Render("🟢 Server Status: Online")
	}
	sb.WriteString(" " + statusLine + "\n")

	return sidebarStyle.Width(w).Height(h).Render(sb.String())
}

// ─── List ────────────────────────────────────────────────────────────────────

func (m *Model) renderList(w, h int) string {
	base := lipgloss.NewStyle().Width(w).Height(h)
	if m.loading {
		return base.Render("\n  " + spinFrames[m.spinner] + "  Loading...")
	}
	items := m.filteredItems()
	catLabel := m.selectedCat().label
	if m.mode == modeSearch {
		catLabel = "Search: " + m.searchQuery + "▋"
	}
	headerText := catLabel
	header := listHeaderStyle.Render(fmt.Sprintf("  %s  (%d)", headerText, len(items)))

	var rows []string
	rows = append(rows, header)

	if len(items) == 0 {
		rows = append(rows, "")
		cat := m.selectedCat()
		var emptyHint string
		switch {
		case cat.trashed:
			emptyHint = "  Trash is empty"
		case cat.archived:
			emptyHint = "  Archive is empty"
		default:
			emptyHint = "  No items. Press n."
		}
		rows = append(rows, dimStyle.Render(emptyHint))
	}

	for i, item := range items {
		name := item.GetMetadata()
		if name == "" {
			name = item.GetId()[:8]
		}
		sub := itemSubtitle(item)
		selected := i == m.listIdx

		// Цветная иконка с фоном
		iconBadge := itemIconBadgeForItem(item)

		// Теги: избранное, папка, 2FA
		var tags string
		if isFavorite(item) {
			tags += "⭐ "
		}
		if f := getItemFolder(item); f != "" && m.selectedCat().folder == "" {
			tags += listFolderTagStyle.Render(" "+f+" ") + " "
		}
		if has2FA(item) {
			tags += list2FABadgeStyle.Render("2FA") + " "
		}

		nameText := truncate(name, 28)
		subText := truncate(sub, 32)

		if i > 0 {
			rows = append(rows, dimStyle.Render("  "+strings.Repeat("·", w-4)))
		}
		if selected {
			nameRow := listSelectedStyle.Width(w).Render("  " + iconBadge + "  " + nameText + "  " + tags)
			subRow := listSelectedSubStyle.Width(w).Render("        " + subText)
			rows = append(rows, nameRow, subRow)
		} else {
			nameRow := listItemStyle.Width(w).Render("  " + iconBadge + "  " + nameText + "  " + tags)
			subRow := listSubStyle.Width(w).Render("        " + subText)
			rows = append(rows, nameRow, subRow)
		}
	}

	return base.Render(lipgloss.JoinVertical(lipgloss.Left, rows...))
}

// itemIconBadge renders a styled icon square with colored background per item type.
func itemIconBadgeForItem(item *commonpb.VaultItem) string {
	if isFileItem(item) {
		return listIconDefaultStyle.Render("📎")
	}
	if isSSHKey(item) {
		return listIconNoteStyle.Render("🗝")
	}
	switch item.GetType() {
	case commonpb.ItemType_CREDENTIAL:
		return listIconLoginStyle.Render("🔑")
	case commonpb.ItemType_CARD:
		return listIconCardStyle.Render("💳")
	case commonpb.ItemType_TEXT:
		return listIconNoteStyle.Render("📄")
	case commonpb.ItemType_OTP:
		return listIconOtpStyle.Render("🔐")
	case commonpb.ItemType_BINARY:
		return listIconIdStyle.Render("👤")
	}
	return listIconDefaultStyle.Render("📁")
}

func has2FA(item *commonpb.VaultItem) bool {
	if item.GetType() == commonpb.ItemType_OTP {
		return true
	}
	p := parseLoginPayload(item.GetPayload(), "")
	return p.TOTPKey != ""
}

func itemSubtitle(item *commonpb.VaultItem) string {
	switch item.GetType() {
	case commonpb.ItemType_CREDENTIAL:
		p := parseLoginPayload(item.GetPayload(), "")
		if p.Username != "" {
			return p.Username
		}
	case commonpb.ItemType_CARD:
		p := parseCardPayload(item.GetPayload(), "")
		if p.Number != "" && len(p.Number) >= 4 {
			return "•••• " + p.Number[len(p.Number)-4:]
		}
	case commonpb.ItemType_OTP:
		p := parseAuthPayload(item.GetPayload(), "")
		if p.Issuer != "" {
			return p.Issuer
		}
	}
	return ""
}

// ─── Detail ──────────────────────────────────────────────────────────────────

func (m *Model) renderDetail(w, h int) string {
	panel := detailPanelStyle.Width(w).Height(h)
	items := m.filteredItems()
	if len(items) == 0 || m.listIdx >= len(items) {
		return panel.Render(m.renderWelcome(w))
	}
	item := items[m.listIdx]

	if w < 10 {
		return panel.Render("…")
	}
	tw := w - 4 // text width inside panel
	var sb strings.Builder
	sb.WriteString("\n")
	name := item.GetMetadata()
	if name == "" {
		name = item.GetId()[:8]
	}
	badge := itemIconBadgeForItem(item)
	favMark := ""
	if isFavorite(item) {
		favMark = " ⭐"
	}
	sb.WriteString(" " + badge + "  " + detailTitleStyle.Render(truncate(name, tw-6)+favMark) + "\n")
	if f := getItemFolder(item); f != "" {
		sb.WriteString("      " + detailFolderTagStyle.Render("  "+f+"  ") + "\n")
	}
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render(" "+strings.Repeat("─", tw)) + "\n\n")

	if isFileItem(item) {
		p := parseFilePayload(item.GetPayload(), item.GetMetadata())
		sb.WriteString(detailSectionStyle.Render(" FILE ATTACHMENT") + "\n")
		sb.WriteString(dField("📎", "File Name", p.FileName, tw))
		sb.WriteString(dField("📦", "Size", FormatFileSize(p.Size), tw))
		sb.WriteString(dField("🗂", "MIME Type", p.MimeType, tw))
		if m.toast != "" {
			sb.WriteString("\n" + toastStyle.Render(" ✓  "+m.toast) + "\n")
		}
		if m.lastErr != "" {
			sb.WriteString("\n" + errorStyle.Render(" ✗  "+truncate(m.lastErr, tw)) + "\n")
		}
		return panel.Render(sb.String())
	}

	if isSSHKey(item) {
		p := parseSSHKeyPayload(item.GetPayload(), item.GetMetadata())
		sb.WriteString(detailSectionStyle.Render(" SSH KEY") + "\n")
		if p.KeyType != "" {
			sb.WriteString(dField("🗝", "Type", p.KeyType, tw))
		}
		if p.PublicKey != "" {
			sb.WriteString(dField("📋", "Public Key", truncate(p.PublicKey, tw-6), tw))
		}
		if p.PrivateKey != "" {
			if m.revealPwd {
				sb.WriteString(dFieldStyled("🔒", "Private Key", truncate(p.PrivateKey, tw-6), detailRevealedStyle))
			} else {
				sb.WriteString(dField("🔒", "Private Key", "-----BEGIN ... KEY-----", tw))
			}
		}
		if p.Comment != "" {
			sb.WriteString(dField("💬", "Comment", p.Comment, tw))
		}
		if m.toast != "" {
			sb.WriteString("\n" + toastStyle.Render(" ✓  "+m.toast) + "\n")
		}
		if m.lastErr != "" {
			sb.WriteString("\n" + errorStyle.Render(" ✗  "+truncate(m.lastErr, tw)) + "\n")
		}
		return panel.Render(sb.String())
	}

	switch item.GetType() {
	case commonpb.ItemType_CREDENTIAL:
		m.renderLoginDetail(&sb, item, tw)
	case commonpb.ItemType_CARD:
		m.renderCardDetail(&sb, item, tw)
	case commonpb.ItemType_TEXT:
		p := parseNotePayload(item.GetPayload(), item.GetMetadata())
		sb.WriteString(dField("📝", "Note", p.Content, tw))
	case commonpb.ItemType_BINARY:
		p := parseIdentityPayload(item.GetPayload(), item.GetMetadata())
		if p.FirstName != "" || p.LastName != "" {
			sb.WriteString(dField("👤", "Name", p.FirstName+" "+p.LastName, tw))
		}
		if p.Email != "" {
			sb.WriteString(dField("✉", "Email", p.Email, tw))
		}
		if p.Phone != "" {
			sb.WriteString(dField("📞", "Phone", p.Phone, tw))
		}
		if p.Company != "" {
			sb.WriteString(dField("🏢", "Company", p.Company, tw))
		}
	case commonpb.ItemType_OTP:
		m.renderAuthDetail(&sb, item)
	}

	if m.toast != "" {
		sb.WriteString("\n" + toastStyle.Render(" ✓  "+m.toast) + "\n")
	}
	if m.lastErr != "" {
		sb.WriteString("\n" + errorStyle.Render(" ✗  "+truncate(m.lastErr, tw)) + "\n")
	}

	return panel.Render(sb.String())
}

func (m *Model) renderLoginDetail(sb *strings.Builder, item *commonpb.VaultItem, tw int) {
	p := parseLoginPayload(item.GetPayload(), item.GetMetadata())

	if p.Username != "" {
		sb.WriteString(dField("👤", "Username", p.Username, tw))
	}
	if p.Password != "" {
		if m.revealPwd {
			sb.WriteString(dFieldStyled("🔑", "Password", truncate(p.Password, tw-6), detailRevealedStyle))
		} else {
			sb.WriteString(dField("🔑", "Password", strings.Repeat("•", 12), tw))
		}
	}
	if p.URL != "" {
		sb.WriteString(dField("🌐", "Website", truncate(p.URL, tw-6), tw))
	}
	if p.TOTPKey != "" {
		code := m.generateTOTP(p.TOTPKey)
		remaining := 30 - (m.now.Unix() % 30)
		sb.WriteString("\n " + detailSectionStyle.Render("2FA") + "\n")
		sb.WriteString(" " + detailRevealedStyle.Render(formatTOTP(code)) + "  " +
			otpTimerStyle.Render(fmt.Sprintf("(%ds)", remaining)) + "\n")
		sb.WriteString(" " + totpBar(remaining, tw-2) + "\n")
	}
	if p.Notes != "" {
		sb.WriteString(dField("📝", "Notes", truncate(p.Notes, tw-6), tw))
	}
	if len(p.History) > 0 {
		sb.WriteString("\n " + detailSectionStyle.Render("Password History") + "\n")
		limit := len(p.History)
		if limit > 5 {
			limit = 5
		}
		for _, h := range p.History[:limit] {
			masked := strings.Repeat("•", 12)
			if m.revealPwd {
				masked = truncate(h.Password, tw-14)
			}
			sb.WriteString(detailHistoryStyle.Render(
				fmt.Sprintf("  %s  %s", h.LastUsed.Format("02.01.06"), masked),
			) + "\n")
		}
	}
}

func (m *Model) renderCardDetail(sb *strings.Builder, item *commonpb.VaultItem, tw int) {
	p := parseCardPayload(item.GetPayload(), item.GetMetadata())
	if p.CardholderName != "" {
		sb.WriteString(dField("👤", "Cardholder", p.CardholderName, tw))
	}
	if p.Number != "" {
		num := p.Number
		if !m.revealPwd && len(num) > 4 {
			num = "•••• •••• •••• " + num[len(num)-4:]
		}
		sb.WriteString(dField("💳", "Card Number", num, tw))
	}
	if p.ExpMonth != "" || p.ExpYear != "" {
		sb.WriteString(dField("📅", "Expires", p.ExpMonth+"/"+p.ExpYear, tw))
	}
	if p.CVV != "" {
		cvv := "•••"
		if m.revealPwd {
			cvv = p.CVV
		}
		sb.WriteString(dField("🔒", "CVV", cvv, tw))
	}
	if p.Notes != "" {
		sb.WriteString(dField("📝", "Notes", truncate(p.Notes, tw-6), tw))
	}
}

func (m *Model) renderAuthDetail(sb *strings.Builder, item *commonpb.VaultItem) {
	p := parseAuthPayload(item.GetPayload(), item.GetMetadata())
	if p.Issuer != "" {
		sb.WriteString(detailLabelStyle.Render(" 🏢  Issuer") + "\n")
		sb.WriteString(detailValueStyle.Render("    "+p.Issuer) + "\n")
	}
	if p.Secret != "" {
		code := m.generateTOTP(p.Secret)
		remaining := 30 - (m.now.Unix() % 30)
		sb.WriteString("\n " + detailSectionStyle.Render("2FA Code") + "\n")
		sb.WriteString(" " + detailRevealedStyle.Render(formatTOTP(code)) + "  " +
			otpTimerStyle.Render(fmt.Sprintf("(%ds)", remaining)) + "\n")
		sb.WriteString(" " + totpBar(remaining, 20) + "\n")
	}
}

func formatTOTP(code string) string {
	if len(code) == 6 {
		return code[:3] + " " + code[3:]
	}
	return code
}

func totpBar(remaining int64, width int) string {
	filled := int(float64(width) * float64(remaining) / 30.0)
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	if remaining <= 5 {
		return otpDangerStyle.Render(bar)
	}
	if remaining <= 10 {
		return otpTimerStyle.Render(bar)
	}
	return otpSafeStyle.Render(bar)
}

// dField renders a labeled field that uses the full width tw.
func dField(icon, label, value string, tw int) string {
	lbl := detailLabelStyle.Render(" " + icon + "  " + label)
	val := detailValueStyle.Render("    " + value)
	sep := dimStyle.Render(" " + strings.Repeat("·", tw))
	return lbl + "\n" + val + "\n" + sep + "\n"
}

func dFieldStyled(icon, label, value string, style lipgloss.Style) string {
	lbl := detailLabelStyle.Render(" " + icon + "  " + label)
	val := style.Render("    " + value)
	return lbl + "\n" + val + "\n"
}

// ─── Welcome screen ──────────────────────────────────────────────────────────

func (m *Model) renderWelcome(_ int) string {
	return dimStyle.Render("\n  Select an item")
}

// ─── Status bar ──────────────────────────────────────────────────────────────

func (m *Model) renderStatus() string {
	if m.mode == modeSearch {
		return statusBarStyle.Width(m.width).Render(
			"  🔍 Search: " + m.searchQuery + "▋" + "   Esc — exit search")
	}
	cat := m.selectedCat()
	var hints []string
	if cat.trashed {
		hints = []string{
			hk("d", "delete forever"),
			hk("R", "restore"),
			hk("Tab", "category"),
			hk("q", "quit"),
		}
	} else if cat.archived {
		hints = []string{
			hk("a", "unarchive"),
			hk("R", "restore"),
			hk("d", "trash"),
			hk("Tab", "category"),
			hk("q", "quit"),
		}
	} else {
		items := m.filteredItems()
		var selItem *commonpb.VaultItem
		if m.listIdx >= 0 && m.listIdx < len(items) {
			selItem = items[m.listIdx]
		}

		isFile := selItem != nil && isFileItem(selItem)
		isSSH := selItem != nil && isSSHKey(selItem)
		isLogin := selItem != nil && (selItem.GetType() == commonpb.ItemType_CREDENTIAL)
		hasURL := isLogin && func() bool {
			p := parseLoginPayload(selItem.GetPayload(), selItem.GetMetadata())
			return p.URL != ""
		}()

		hints = []string{hk("n", "new"), hk("e", "edit")}
		if !isFile {
			hints = append(hints, hk("D", "duplicate"))
		}
		hints = append(hints, hk("f", "favorite"))
		if hasURL {
			hints = append(hints, hk("o", "open URL"))
		}
		hints = append(hints, hk("a", "archive"), hk("d", "trash"))
		if isLogin {
			hints = append(hints, hk("c", "copy password"), hk("u", "copy username"), hk("p", "reveal"))
		}
		if selItem != nil && selItem.GetType() == commonpb.ItemType_OTP {
			hints = append(hints, hk("c", "copy TOTP"))
		}
		if isSSH {
			hints = append(hints, hk("c", "copy key"))
		}
		if isFile {
			hints = append(hints, hk("x", "export file"))
		}
		if isLogin {
			hints = append(hints, hk("g", "generator"))
		}
		hints = append(hints, hk("S", "sort"), hk("/", "search"), hk("r", "sync"), hk("q", "quit"))
	}
	return keyHintStyle.Width(m.width).Render("  " + strings.Join(hints, "  "))
}

// ─── Picker overlay ──────────────────────────────────────────────────────────

func (m *Model) viewWithOverlay(overlay string) string {
	bg := m.viewList()
	ow := lipgloss.Width(overlay)
	oh := lipgloss.Height(overlay)
	x := (m.width - ow) / 2
	y := (m.height - oh) / 2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	return placeover(bg, overlay, x, y)
}

func (m *Model) viewPicker() string {
	var sb strings.Builder
	sb.WriteString("New Item\n")
	sb.WriteString(strings.Repeat("-", 16) + "\n")
	for i, e := range pickerEntries {
		if i == m.pickerIdx {
			sb.WriteString("> " + e.label + "\n")
		} else {
			sb.WriteString("  " + e.label + "\n")
		}
	}
	sb.WriteString(strings.Repeat("-", 16) + "\n")
	sb.WriteString("Enter  Esc")
	return overlayStyle.Render(sb.String())
}

// ─── Delete confirm overlay ──────────────────────────────────────────────────

func (m *Model) viewDeleteConfirm() string {
	name := "this item"
	if m.deleteTarget != nil {
		name = m.deleteTarget.GetMetadata()
	}
	var sb strings.Builder
	sb.WriteString(lipgloss.NewStyle().Foreground(c(colorRed)).Bold(true).Render("Move to Trash") + "\n\n")
	sb.WriteString(lipgloss.NewStyle().Foreground(c(colorText)).Render("«"+truncate(name, 32)+"»") + "\n\n")
	sb.WriteString(dimStyle.Render("This action cannot be undone.") + "\n\n")
	sb.WriteString(keyHintStyle.Render(keyStyle.Render("y") + " confirm   " + keyStyle.Render("Esc") + " cancel"))
	return overlayStyle.Render(sb.String())
}

// ─── Form view ────────────────────────────────────────────────────────────────

func (m *Model) viewForm() string {
	f := m.form
	action := "New"
	if f.editItemID != "" {
		action = "Edit"
	}

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(headerStyle.Width(m.width).Render(
		fmt.Sprintf("GophKeeper  ·  %s %s", action, f.title)) + "\n\n")

	for i, field := range f.fields {
		active := i == f.focusIdx
		var labelS string
		if active {
			labelS = formLabelActiveStyle.Render("  › " + field.label)
		} else {
			labelS = formLabelStyle.Render("    " + field.label)
		}
		sb.WriteString(labelS + "\n")
		sb.WriteString("    " + field.input.View() + "\n")
		if field.hint != "" {
			sb.WriteString(dimStyle.Render("      "+field.hint) + "\n")
		}
		sb.WriteString("\n")
	}

	if m.lastErr != "" {
		sb.WriteString(errorStyle.Render("  ✗ "+m.lastErr) + "\n\n")
	}

	hasGen := false
	for _, field := range m.form.fields {
		if field.canGen {
			hasGen = true
			break
		}
	}
	hints := "  " + hk("Tab", "next") + "  " + hk("Ctrl+S", "save") + "  "
	if hasGen {
		hints += hk("Ctrl+G", "generate password") + "  "
	}
	hints += hk("Esc", "cancel")
	sb.WriteString(keyHintStyle.Render(hints))

	return sb.String()
}

// ─── Overlay placement ───────────────────────────────────────────────────────

// placeover draws overlay on top of base at position (x, y).
// x and y are measured in terminal columns (wide chars count as 2).
func placeover(base, overlay string, x, y int) string {
	baseLines := strings.Split(base, "\n")
	overlayLines := strings.Split(overlay, "\n")
	result := make([]string, len(baseLines))
	copy(result, baseLines)

	for i, ol := range overlayLines {
		row := y + i
		if row < 0 || row >= len(result) {
			continue
		}
		bl := result[row]
		blCols := visColWidth(bl)
		olCols := visColWidth(ol)

		if x > blCols {
			result[row] = bl + strings.Repeat(" ", x-blCols) + ol
		} else {
			endCol := x + olCols
			left := byteOffsetForCol(bl, x)
			right := byteOffsetForCol(bl, endCol)
			result[row] = bl[:left] + ol + bl[right:]
		}
	}
	return strings.Join(result, "\n")
}

// visColWidth returns the number of terminal columns occupied by the visible
// (non-ANSI) content of s, accounting for wide characters (emoji, CJK, etc.).
func visColWidth(s string) int {
	cols := 0
	inEsc := false
	for _, r := range s {
		if r == '\x1b' {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		cols += runewidth.RuneWidth(r)
	}
	return cols
}

// byteOffsetForCol returns the byte offset in s where the visible column col
// begins, correctly handling wide characters and ANSI escape sequences.
func byteOffsetForCol(s string, col int) int {
	curCol := 0
	inEsc := false
	for i, r := range s {
		if r == '\x1b' {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		if curCol >= col {
			return i
		}
		curCol += runewidth.RuneWidth(r)
	}
	return len(s)
}

// ─── Misc helpers ─────────────────────────────────────────────────────────────

func hk(k, label string) string {
	return keyStyle.Render(k) + " " + label
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return string(runes[:n-1]) + "…"
}
