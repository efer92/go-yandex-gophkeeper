package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// PassphraseOpts controls passphrase generation.
type PassphraseOpts struct {
	Words      int    // number of words (default 5)
	Separator  string // word separator (default "-")
	Capitalize bool   // capitalize first letter of each word
	IncludeNum bool   // append a random 4-digit number
}

// DefaultPassphraseOpts returns strong passphrase defaults.
func DefaultPassphraseOpts() PassphraseOpts {
	return PassphraseOpts{
		Words:      5,
		Separator:  "-",
		Capitalize: true,
		IncludeNum: true,
	}
}

// GeneratePassphrase creates a random passphrase from the built-in wordlist.
// Entropy: log2(512^5) ≈ 45 bits for 5 words; log2(512^6) ≈ 54 bits for 6 words.
func GeneratePassphrase(opts PassphraseOpts) (string, error) {
	n := opts.Words
	if n < 2 {
		n = 2
	}
	wl := int64(len(passphraseWordlist))
	words := make([]string, n)
	for i := range words {
		idx, err := rand.Int(rand.Reader, big.NewInt(wl))
		if err != nil {
			return "", fmt.Errorf("rand: %w", err)
		}
		w := passphraseWordlist[idx.Int64()]
		if opts.Capitalize && len(w) > 0 {
			w = strings.ToUpper(w[:1]) + w[1:]
		}
		words[i] = w
	}
	result := strings.Join(words, opts.Separator)
	if opts.IncludeNum {
		numBig, err := rand.Int(rand.Reader, big.NewInt(9000))
		if err != nil {
			return "", fmt.Errorf("rand num: %w", err)
		}
		result += opts.Separator + fmt.Sprintf("%d", numBig.Int64()+1000)
	}
	return result, nil
}

// passphraseWordlist — 512 common, memorable English words curated for clarity.
var passphraseWordlist = []string{
	"able", "acid", "aged", "also", "area", "army", "away", "baby",
	"back", "ball", "band", "bank", "base", "bath", "bear", "beat",
	"bell", "best", "bird", "blow", "blue", "bold", "bond", "bone",
	"book", "boot", "born", "bowl", "burn", "calm", "came", "camp",
	"card", "care", "cart", "case", "cash", "cast", "cave", "cell",
	"chip", "city", "clan", "clay", "clip", "club", "coal", "coat",
	"code", "coin", "cold", "comb", "come", "cook", "cool", "copy",
	"core", "corn", "cost", "crew", "crop", "cube", "cure", "curl",
	"dame", "damp", "dare", "dark", "dash", "data", "dawn", "days",
	"dead", "deal", "dean", "deep", "deer", "desk", "dirt", "disk",
	"doll", "dome", "door", "dose", "down", "draw", "drop", "drum",
	"dual", "dusk", "dust", "duty", "each", "earn", "ease", "east",
	"edge", "epic", "even", "ever", "exam", "face", "fact", "fail",
	"fair", "fall", "fame", "farm", "fast", "fate", "felt", "file",
	"fill", "film", "find", "fire", "fish", "fist", "flag", "flat",
	"flew", "flip", "flow", "foam", "folk", "font", "food", "foot",
	"ford", "fork", "form", "fort", "four", "free", "from", "fuel",
	"full", "fund", "fury", "fuse", "gain", "game", "gate", "gave",
	"gear", "gift", "girl", "glad", "glow", "glue", "goal", "gold",
	"golf", "gone", "good", "grab", "gram", "gray", "grew", "grid",
	"grim", "grip", "grow", "gulf", "guru", "hand", "hang", "hard",
	"harm", "hash", "haul", "have", "hawk", "head", "heat", "heel",
	"held", "helm", "help", "hero", "high", "hike", "hill", "hint",
	"hold", "hole", "home", "hook", "hope", "horn", "host", "hour",
	"huge", "hull", "hunt", "hurt", "icon", "idea", "idle", "inch",
	"iron", "item", "jade", "jazz", "jest", "join", "jump", "just",
	"keen", "kept", "kind", "king", "knot", "know", "lack", "lake",
	"lamp", "land", "last", "late", "lead", "leaf", "lean", "leap",
	"left", "lens", "less", "life", "lift", "like", "lime", "line",
	"link", "lion", "list", "load", "lock", "loft", "lone", "long",
	"look", "loop", "loss", "lost", "loud", "love", "luck", "made",
	"main", "make", "mall", "many", "mark", "mars", "mask", "math",
	"maze", "meal", "meet", "melt", "menu", "mesa", "mesh", "mind",
	"mint", "miss", "mist", "mode", "monk", "moon", "more", "most",
	"move", "much", "mute", "myth", "name", "navy", "near", "neck",
	"need", "nest", "next", "nice", "nine", "node", "none", "noon",
	"norm", "note", "nova", "null", "oath", "once", "only", "open",
	"oral", "orca", "over", "pace", "pack", "page", "paid", "pain",
	"pair", "palm", "park", "part", "pass", "path", "peak", "peer",
	"pick", "pier", "pine", "pink", "plan", "play", "plot", "plow",
	"plus", "poet", "pole", "poll", "pond", "pool", "poor", "port",
	"post", "pour", "prey", "pure", "push", "quad", "race", "rack",
	"ramp", "rank", "read", "real", "reef", "rely", "rent", "rest",
	"rice", "rich", "ride", "ring", "rise", "risk", "road", "rock",
	"role", "roll", "roof", "room", "root", "rope", "rose", "ruin",
	"rule", "rush", "safe", "sail", "sake", "sale", "salt", "same",
	"save", "scan", "seal", "seed", "seek", "seem", "self", "sell",
	"send", "ship", "shoe", "shop", "shot", "show", "side", "sign",
	"silk", "silt", "site", "size", "skin", "skip", "slab", "slam",
	"slim", "slip", "slow", "snap", "snow", "soft", "soil", "sole",
	"some", "song", "sort", "soul", "span", "spin", "spot", "star",
	"stay", "stem", "step", "stop", "such", "suit", "surf", "swap",
	"swim", "tail", "task", "team", "tear", "tell", "term", "text",
	"than", "them", "then", "they", "thin", "this", "tile", "time",
	"tiny", "tire", "toll", "tone", "tool", "tops", "tour", "town",
	"trap", "trek", "trim", "trio", "true", "tube", "tune", "turn",
	"type", "unit", "upon", "used", "user", "vast", "verb", "very",
	"view", "vine", "void", "volt", "vote", "wade", "wage", "wake",
	"walk", "wall", "warm", "warp", "wary", "wave", "weak", "wear",
	"weed", "well", "went", "were", "west", "what", "when", "wide",
	"wild", "will", "wind", "wine", "wire", "wise", "wish", "with",
	"wolf", "wood", "word", "wore", "work", "worm", "worn", "wrap",
	"yard", "year", "your", "zero", "zinc", "zone", "zoom", "barn",
}
