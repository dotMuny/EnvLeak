package rules

import (
	"sort"
	"strconv"
)

// matcher is an Aho-Corasick automaton over every keyword in the catalogue.
//
// The naive prefilter — "for each rule, for each keyword, strings.Contains" —
// is O(rules x keywords x len(line)). With ~50 rules that is ~150 substring
// searches per line of every file in the repository. Aho-Corasick walks the
// line once, in O(len(line)), and reports which rules woke up. That single
// pass is what keeps the whole-repository scan in the seconds range; see
// BenchmarkPrefilter and docs/decisions.md.
//
// The automaton is immutable once built, so it is safe to share across the
// worker pool without locking.
type matcher struct {
	next   [][256]int32
	fail   []int32
	output [][]int32 // rule indices reported when entering this state
	empty  bool
}

func newMatcher(patterns [][]string) *matcher {
	m := &matcher{}
	m.addState() // root == 0

	total := 0
	for rule, kws := range patterns {
		for _, kw := range kws {
			total++
			state := int32(0)
			for i := 0; i < len(kw); i++ {
				c := kw[i]
				if m.next[state][c] == 0 {
					m.next[state][c] = m.addState()
				}
				state = m.next[state][c]
			}
			m.output[state] = append(m.output[state], int32(rule))
		}
	}
	m.empty = total == 0
	m.buildFailureLinks()
	return m
}

// maxStates bounds the automaton. The built-in catalogue builds a few hundred
// states; a catalogue large enough to reach this limit is a configuration
// error, and overflowing an int32 state id silently would be far worse than
// refusing to build.
const maxStates = 1 << 20

func (m *matcher) addState() int32 {
	if len(m.next) >= maxStates {
		panic("rules: keyword automaton exceeded " + itoa(maxStates) + " states")
	}
	m.next = append(m.next, [256]int32{})
	m.fail = append(m.fail, 0)
	m.output = append(m.output, nil)
	return int32(len(m.next) - 1) //nolint:gosec // bounded by maxStates above
}

func itoa(n int) string { return strconv.Itoa(n) }

// buildFailureLinks runs the standard BFS over the trie, and while it is there
// converts the goto function into a full DFA (every state has a transition for
// every byte) so that match never has to follow failure links at scan time.
func (m *matcher) buildFailureLinks() {
	queue := make([]int32, 0, len(m.next))
	for c := 0; c < 256; c++ {
		if s := m.next[0][c]; s != 0 {
			m.fail[s] = 0
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		// Inherit the outputs of the longest proper suffix that is also a
		// keyword, so a single state lookup yields every match ending here.
		if f := m.fail[state]; len(m.output[f]) > 0 {
			m.output[state] = append(m.output[state], m.output[f]...)
		}
		for c := 0; c < 256; c++ {
			nxt := m.next[state][c]
			if nxt == 0 {
				m.next[state][c] = m.next[m.fail[state]][c]
				continue
			}
			m.fail[nxt] = m.next[m.fail[state]][c]
			queue = append(queue, nxt)
		}
	}
}

// match appends the indices of every rule with a keyword occurring in line to
// dst, deduplicated and sorted. line must already be lowercased.
func (m *matcher) match(line []byte, dst []int) []int {
	if m.empty {
		return dst
	}
	start := len(dst)
	state := int32(0)
	for i := 0; i < len(line); i++ {
		state = m.next[state][line[i]]
		if out := m.output[state]; len(out) > 0 {
			for _, r := range out {
				dst = append(dst, int(r))
			}
		}
	}
	hits := dst[start:]
	if len(hits) < 2 {
		return dst
	}
	sort.Ints(hits)
	n := 1
	for i := 1; i < len(hits); i++ {
		if hits[i] != hits[n-1] {
			hits[n] = hits[i]
			n++
		}
	}
	return dst[:start+n]
}
