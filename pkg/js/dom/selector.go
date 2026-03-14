package dom

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// ──────────────────────────────────────────────
// Selector AST
// ──────────────────────────────────────────────

// SelectorGroup is a comma-separated list of selectors (e.g., "h1, h2, h3").
type SelectorGroup struct {
	Selectors []*ComplexSelector
}

// ComplexSelector is a chain of compound selectors connected by combinators.
// e.g., "div > p.cls span" = [div, >, p.cls, ' ', span]
type ComplexSelector struct {
	Parts []SelectorPart
}

// SelectorPart is either a compound selector or a combinator.
type SelectorPart struct {
	Compound   *CompoundSelector
	Combinator rune // ' ' (descendant), '>' (child), '+' (adjacent), '~' (general sibling)
}

// CompoundSelector is a sequence of simple selectors that all must match.
// e.g., "div.cls#id[attr]" = tag=div, id=id, classes=[cls], attrs=[attr]
type CompoundSelector struct {
	Tag          string // "*" or tag name, "" means any
	ID           string
	Classes      []string
	Attrs        []AttrSelector
	PseudoClasses []PseudoSelector
	Not          *CompoundSelector // :not() argument
}

// AttrSelector represents [attr], [attr=val], [attr~=val], etc.
type AttrSelector struct {
	Key      string
	Op       string // "" (presence), "=" (exact), "~=" (word), "|=" (prefix-dash), "^=" (prefix), "$=" (suffix), "*=" (contains)
	Value    string
	CaseInsensitive bool
}

// PseudoSelector represents pseudo-classes like :first-child, :nth-child(n).
type PseudoSelector struct {
	Name string
	Arg  string // for functional pseudo-classes like :nth-child(2n+1)
}

// ──────────────────────────────────────────────
// Parser
// ──────────────────────────────────────────────

type selectorParser struct {
	input string
	pos   int
}

// ParseSelector parses a CSS selector string into a SelectorGroup.
func ParseSelector(s string) (*SelectorGroup, error) {
	p := &selectorParser{input: strings.TrimSpace(s)}
	group, err := p.parseGroup()
	if err != nil {
		return nil, err
	}
	return group, nil
}

func (p *selectorParser) parseGroup() (*SelectorGroup, error) {
	group := &SelectorGroup{}
	for {
		p.skipWhitespace()
		sel, err := p.parseComplex()
		if err != nil {
			return nil, err
		}
		group.Selectors = append(group.Selectors, sel)
		p.skipWhitespace()
		if p.pos >= len(p.input) {
			break
		}
		if p.peek() == ',' {
			p.pos++ // consume comma
		} else {
			break
		}
	}
	return group, nil
}

func (p *selectorParser) parseComplex() (*ComplexSelector, error) {
	cs := &ComplexSelector{}
	p.skipWhitespace()
	// First compound
	compound, err := p.parseCompound()
	if err != nil {
		return nil, err
	}
	cs.Parts = append(cs.Parts, SelectorPart{Compound: compound})

	for p.pos < len(p.input) {
		// Check for combinator
		hadSpace := p.skipWhitespace()
		if p.pos >= len(p.input) || p.peek() == ',' {
			break
		}

		var combinator rune
		ch := p.peek()
		switch ch {
		case '>':
			combinator = '>'
			p.pos++
			p.skipWhitespace()
		case '+':
			combinator = '+'
			p.pos++
			p.skipWhitespace()
		case '~':
			combinator = '~'
			p.pos++
			p.skipWhitespace()
		default:
			if hadSpace {
				combinator = ' ' // descendant
			} else {
				goto endLoop
			}
		}

		if combinator == 0 {
			break
		}

		compound, err := p.parseCompound()
		if err != nil {
			return nil, err
		}
		cs.Parts = append(cs.Parts, SelectorPart{Combinator: combinator})
		cs.Parts = append(cs.Parts, SelectorPart{Compound: compound})
	}
endLoop:

	return cs, nil
}

func (p *selectorParser) parseCompound() (*CompoundSelector, error) {
	cs := &CompoundSelector{}

	if p.pos >= len(p.input) {
		return nil, fmt.Errorf("unexpected end of selector")
	}

	// Parse tag name or *
	if p.peek() == '*' {
		cs.Tag = "*"
		p.pos++
	} else if isNameStart(p.peek()) {
		cs.Tag = p.readName()
	}

	// Parse the rest: #id, .class, [attr], :pseudo
	for p.pos < len(p.input) {
		ch := p.peek()
		switch ch {
		case '#':
			p.pos++
			cs.ID = p.readName()
		case '.':
			p.pos++
			cs.Classes = append(cs.Classes, p.readName())
		case '[':
			attr, err := p.parseAttr()
			if err != nil {
				return nil, err
			}
			cs.Attrs = append(cs.Attrs, attr)
		case ':':
			pseudo, err := p.parsePseudo()
			if err != nil {
				return nil, err
			}
			if pseudo.Name == "not" && pseudo.Arg != "" {
				// Parse :not() argument as a compound selector
				subParser := &selectorParser{input: pseudo.Arg}
				notSel, err := subParser.parseCompound()
				if err != nil {
					return nil, fmt.Errorf(":not() argument error: %v", err)
				}
				cs.Not = notSel
			} else {
				cs.PseudoClasses = append(cs.PseudoClasses, pseudo)
			}
		default:
			// End of compound selector
			goto done
		}
	}
done:

	// If nothing was parsed, that's an error
	if cs.Tag == "" && cs.ID == "" && len(cs.Classes) == 0 &&
		len(cs.Attrs) == 0 && len(cs.PseudoClasses) == 0 && cs.Not == nil {
		return nil, fmt.Errorf("empty selector at position %d", p.pos)
	}

	return cs, nil
}

func (p *selectorParser) parseAttr() (AttrSelector, error) {
	p.pos++ // consume '['
	p.skipWhitespace()

	attr := AttrSelector{}
	attr.Key = strings.ToLower(p.readName())
	p.skipWhitespace()

	if p.pos >= len(p.input) {
		return attr, fmt.Errorf("unclosed attribute selector")
	}

	if p.peek() == ']' {
		p.pos++ // presence only
		return attr, nil
	}

	// Read operator
	op := ""
	ch := p.peek()
	switch {
	case ch == '=':
		op = "="
		p.pos++
	case ch == '~' || ch == '|' || ch == '^' || ch == '$' || ch == '*':
		op = string(ch)
		p.pos++
		if p.pos < len(p.input) && p.peek() == '=' {
			op += "="
			p.pos++
		}
	}
	attr.Op = op

	p.skipWhitespace()

	// Read value
	if p.pos < len(p.input) {
		if p.peek() == '"' || p.peek() == '\'' {
			attr.Value = p.readQuotedString()
		} else {
			attr.Value = p.readName()
		}
	}

	p.skipWhitespace()

	// Check for case-insensitive flag
	if p.pos < len(p.input) && (p.peek() == 'i' || p.peek() == 'I') {
		attr.CaseInsensitive = true
		p.pos++
		p.skipWhitespace()
	}

	if p.pos < len(p.input) && p.peek() == ']' {
		p.pos++
	}

	return attr, nil
}

func (p *selectorParser) parsePseudo() (PseudoSelector, error) {
	p.pos++ // consume first ':'

	// Handle :: (just treat as single :)
	if p.pos < len(p.input) && p.peek() == ':' {
		p.pos++
	}

	name := strings.ToLower(p.readName())
	pseudo := PseudoSelector{Name: name}

	// Functional pseudo-class
	if p.pos < len(p.input) && p.peek() == '(' {
		p.pos++ // consume '('
		depth := 1
		start := p.pos
		for p.pos < len(p.input) && depth > 0 {
			if p.input[p.pos] == '(' {
				depth++
			} else if p.input[p.pos] == ')' {
				depth--
			}
			if depth > 0 {
				p.pos++
			}
		}
		pseudo.Arg = strings.TrimSpace(p.input[start:p.pos])
		if p.pos < len(p.input) {
			p.pos++ // consume ')'
		}
	}

	return pseudo, nil
}

func (p *selectorParser) readName() string {
	start := p.pos
	for p.pos < len(p.input) {
		ch := rune(p.input[p.pos])
		if isNameChar(ch) {
			p.pos++
		} else {
			break
		}
	}
	return p.input[start:p.pos]
}

func (p *selectorParser) readQuotedString() string {
	if p.pos >= len(p.input) {
		return ""
	}
	quote := p.input[p.pos]
	p.pos++ // consume opening quote
	var sb strings.Builder
	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		if ch == '\\' && p.pos+1 < len(p.input) {
			p.pos++
			sb.WriteByte(p.input[p.pos])
			p.pos++
			continue
		}
		if ch == quote {
			p.pos++ // consume closing quote
			break
		}
		sb.WriteByte(ch)
		p.pos++
	}
	return sb.String()
}

func (p *selectorParser) skipWhitespace() bool {
	start := p.pos
	for p.pos < len(p.input) && (p.input[p.pos] == ' ' || p.input[p.pos] == '\t' || p.input[p.pos] == '\n' || p.input[p.pos] == '\r') {
		p.pos++
	}
	return p.pos > start
}

func (p *selectorParser) peek() byte {
	if p.pos >= len(p.input) {
		return 0
	}
	return p.input[p.pos]
}

func isNameStart(ch byte) bool {
	r := rune(ch)
	return unicode.IsLetter(r) || ch == '_' || ch == '-'
}

func isNameChar(ch rune) bool {
	return unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '_' || ch == '-'
}

// ──────────────────────────────────────────────
// Matcher
// ──────────────────────────────────────────────

// QueryFirst returns the first descendant matching this selector group.
func (sg *SelectorGroup) QueryFirst(root *Node) *Node {
	var found *Node
	walkAll(root, func(n *Node) bool {
		if n.Type != ElementNode {
			return false
		}
		for _, sel := range sg.Selectors {
			if matchComplex(sel, n) {
				found = n
				return true // stop
			}
		}
		return false
	})
	return found
}

// QueryAll returns all descendants matching this selector group.
func (sg *SelectorGroup) QueryAll(root *Node) []*Node {
	var result []*Node
	walkAll(root, func(n *Node) bool {
		if n.Type != ElementNode {
			return false
		}
		for _, sel := range sg.Selectors {
			if matchComplex(sel, n) {
				result = append(result, n)
				break
			}
		}
		return false
	})
	return result
}

// Match checks if the node matches any selector in the group.
func (sg *SelectorGroup) Match(n *Node) bool {
	for _, sel := range sg.Selectors {
		if matchComplex(sel, n) {
			return true
		}
	}
	return false
}

// walkAll walks all nodes depth-first starting from children of root.
func walkAll(root *Node, fn func(*Node) bool) bool {
	for _, child := range root.Children {
		if fn(child) {
			return true
		}
		if walkAll(child, fn) {
			return true
		}
	}
	return false
}

// matchComplex checks if a node matches a complex selector.
// We match right-to-left: the last compound must match the node,
// then we walk up/left for combinators.
func matchComplex(cs *ComplexSelector, node *Node) bool {
	parts := cs.Parts
	if len(parts) == 0 {
		return false
	}

	// The rightmost compound must match the node
	lastIdx := len(parts) - 1
	if parts[lastIdx].Compound == nil {
		return false
	}
	if !matchCompound(parts[lastIdx].Compound, node) {
		return false
	}

	// Walk backwards through combinator + compound pairs
	current := node
	for i := lastIdx - 1; i >= 0; i -= 2 {
		if i < 1 {
			break
		}
		combinator := parts[i].Combinator
		compound := parts[i-1].Compound
		if compound == nil {
			return false
		}

		switch combinator {
		case ' ': // descendant
			found := false
			for p := current.Parent; p != nil; p = p.Parent {
				if p.Type == ElementNode && matchCompound(compound, p) {
					current = p
					found = true
					break
				}
			}
			if !found {
				return false
			}

		case '>': // child
			parent := current.Parent
			if parent == nil || parent.Type != ElementNode || !matchCompound(compound, parent) {
				return false
			}
			current = parent

		case '+': // adjacent sibling
			prev := current.PreviousElementSibling()
			if prev == nil || !matchCompound(compound, prev) {
				return false
			}
			current = prev

		case '~': // general sibling
			found := false
			if current.Parent != nil {
				for _, c := range current.Parent.ChildElements() {
					if c == current {
						break
					}
					if matchCompound(compound, c) {
						current = c
						found = true
						// Don't break — we want the last one before current
					}
				}
			}
			if !found {
				return false
			}
		}
	}

	return true
}

// matchCompound checks if a node matches a compound selector.
func matchCompound(cs *CompoundSelector, n *Node) bool {
	if n.Type != ElementNode {
		return false
	}

	// Tag
	if cs.Tag != "" && cs.Tag != "*" {
		if !strings.EqualFold(n.Tag, cs.Tag) {
			return false
		}
	}

	// ID
	if cs.ID != "" {
		if n.ID() != cs.ID {
			return false
		}
	}

	// Classes
	for _, cls := range cs.Classes {
		if !n.HasClass(cls) {
			return false
		}
	}

	// Attributes
	for _, attr := range cs.Attrs {
		if !matchAttr(attr, n) {
			return false
		}
	}

	// Pseudo-classes
	for _, pseudo := range cs.PseudoClasses {
		if !matchPseudo(pseudo, n) {
			return false
		}
	}

	// :not()
	if cs.Not != nil {
		if matchCompound(cs.Not, n) {
			return false
		}
	}

	return true
}

// matchAttr checks if a node matches an attribute selector.
func matchAttr(sel AttrSelector, n *Node) bool {
	val, exists := n.Attrs[sel.Key]
	if !exists {
		return false
	}
	if sel.Op == "" {
		return true // presence only
	}

	checkVal := val
	selVal := sel.Value
	if sel.CaseInsensitive {
		checkVal = strings.ToLower(checkVal)
		selVal = strings.ToLower(selVal)
	}

	switch sel.Op {
	case "=":
		return checkVal == selVal
	case "~=":
		for _, word := range strings.Fields(checkVal) {
			if word == selVal {
				return true
			}
		}
		return false
	case "|=":
		return checkVal == selVal || strings.HasPrefix(checkVal, selVal+"-")
	case "^=":
		return strings.HasPrefix(checkVal, selVal)
	case "$=":
		return strings.HasSuffix(checkVal, selVal)
	case "*=":
		return strings.Contains(checkVal, selVal)
	}
	return false
}

// matchPseudo checks if a node matches a pseudo-class.
func matchPseudo(pseudo PseudoSelector, n *Node) bool {
	switch pseudo.Name {
	case "first-child":
		return isNthChild(n, 1)
	case "last-child":
		return isLastChild(n)
	case "only-child":
		return isNthChild(n, 1) && isLastChild(n)
	case "first-of-type":
		return isNthOfType(n, 1)
	case "last-of-type":
		return isLastOfType(n)
	case "only-of-type":
		return isNthOfType(n, 1) && isLastOfType(n)
	case "nth-child":
		return matchNth(pseudo.Arg, childIndex(n))
	case "nth-last-child":
		return matchNth(pseudo.Arg, childIndexFromEnd(n))
	case "nth-of-type":
		return matchNth(pseudo.Arg, typeIndex(n))
	case "nth-last-of-type":
		return matchNth(pseudo.Arg, typeIndexFromEnd(n))
	case "empty":
		return len(n.Children) == 0
	case "root":
		if n.Parent != nil {
			return n.Parent.Type == DocumentNode
		}
		return false
	case "enabled":
		_, disabled := n.Attrs["disabled"]
		return !disabled
	case "disabled":
		_, disabled := n.Attrs["disabled"]
		return disabled
	case "checked":
		_, checked := n.Attrs["checked"]
		return checked
	case "contains":
		// Non-standard but common: :contains("text")
		text := strings.Trim(pseudo.Arg, `"' `)
		return strings.Contains(n.TextContent(), text)
	}
	return false
}

// ──────────────────────────────────────────────
// Position helpers
// ──────────────────────────────────────────────

func childIndex(n *Node) int {
	if n.Parent == nil {
		return 1
	}
	idx := 0
	for _, c := range n.Parent.Children {
		if c.Type == ElementNode {
			idx++
		}
		if c == n {
			return idx
		}
	}
	return 0
}

func childIndexFromEnd(n *Node) int {
	if n.Parent == nil {
		return 1
	}
	total := n.Parent.ChildElementCount()
	return total - childIndex(n) + 1
}

func typeIndex(n *Node) int {
	if n.Parent == nil {
		return 1
	}
	idx := 0
	for _, c := range n.Parent.Children {
		if c.Type == ElementNode && c.Tag == n.Tag {
			idx++
		}
		if c == n {
			return idx
		}
	}
	return 0
}

func typeIndexFromEnd(n *Node) int {
	if n.Parent == nil {
		return 1
	}
	count := 0
	for _, c := range n.Parent.Children {
		if c.Type == ElementNode && c.Tag == n.Tag {
			count++
		}
	}
	return count - typeIndex(n) + 1
}

func isNthChild(n *Node, pos int) bool {
	return childIndex(n) == pos
}

func isLastChild(n *Node) bool {
	if n.Parent == nil {
		return true
	}
	elems := n.Parent.ChildElements()
	return len(elems) > 0 && elems[len(elems)-1] == n
}

func isNthOfType(n *Node, pos int) bool {
	return typeIndex(n) == pos
}

func isLastOfType(n *Node) bool {
	if n.Parent == nil {
		return true
	}
	var last *Node
	for _, c := range n.Parent.Children {
		if c.Type == ElementNode && c.Tag == n.Tag {
			last = c
		}
	}
	return last == n
}

// matchNth evaluates an An+B expression against an index.
// Supports: "odd", "even", "3", "2n", "2n+1", "-n+3", etc.
func matchNth(expr string, index int) bool {
	if index <= 0 {
		return false
	}
	expr = strings.TrimSpace(strings.ToLower(expr))

	switch expr {
	case "odd":
		return index%2 == 1
	case "even":
		return index%2 == 0
	}

	// Try simple number
	if n, err := strconv.Atoi(expr); err == nil {
		return index == n
	}

	// Parse An+B
	a, b := parseAnB(expr)
	if a == 0 {
		return index == b
	}
	// Check if (index - b) is a non-negative multiple of a
	diff := index - b
	if a > 0 {
		return diff >= 0 && diff%a == 0
	}
	// a < 0: index <= b and (b - index) % |a| == 0
	return diff <= 0 && (-diff)%(-a) == 0
}

// parseAnB parses an An+B expression. Returns (a, b).
func parseAnB(expr string) (int, int) {
	expr = strings.ReplaceAll(expr, " ", "")

	nIdx := strings.Index(expr, "n")
	if nIdx == -1 {
		b, _ := strconv.Atoi(expr)
		return 0, b
	}

	// Parse A
	aStr := expr[:nIdx]
	a := 1
	switch aStr {
	case "":
		a = 1
	case "-":
		a = -1
	case "+":
		a = 1
	default:
		a, _ = strconv.Atoi(aStr)
	}

	// Parse B
	b := 0
	rest := expr[nIdx+1:]
	if rest != "" {
		b, _ = strconv.Atoi(rest)
	}

	return a, b
}
