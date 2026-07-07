package tui

import "os/exec"

// openURL opens url in the default browser cross-platform.
func openURL(url string) {
	for _, args := range [][]string{
		{"open", url},
		{"xdg-open", url},
		{"cmd", "/c", "start", url},
	} {
		if exec.Command(args[0], args[1:]...).Start() == nil {
			return
		}
	}
}
