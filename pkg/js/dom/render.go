package dom

import (
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"strings"
)

// ──────────────────────────────────────────────
// Renderer: layout tree → image.RGBA → PNG
// ──────────────────────────────────────────────

// RenderOptions controls screenshot output.
type RenderOptions struct {
	Width    int    // viewport width (default 1280)
	Height   int    // viewport height (default 720)
	ScrollY  int    // vertical scroll offset
	FullPage bool   // if true, capture entire content height
	Selector string // if set, capture only this element
	Path     string // output path (empty = auto from TempStore)
}

// DefaultRenderOptions returns sensible defaults.
func DefaultRenderOptions() *RenderOptions {
	return &RenderOptions{
		Width:  1280,
		Height: 720,
	}
}

// Screenshot takes a screenshot of the document and saves it as PNG.
// Returns the file path where the screenshot was saved.
func Screenshot(doc *Document, opts *RenderOptions) (string, error) {
	if opts == nil {
		opts = DefaultRenderOptions()
	}
	if opts.Width <= 0 {
		opts.Width = 1280
	}
	if opts.Height <= 0 {
		opts.Height = 720
	}

	// Compute layout
	layout := Layout(doc, opts.Width, opts.Height)

	// Determine capture dimensions
	captureHeight := opts.Height
	if opts.FullPage {
		captureHeight = layout.ContentHeight
		if captureHeight < opts.Height {
			captureHeight = opts.Height
		}
	}

	scrollY := opts.ScrollY
	captureX := 0
	captureY := scrollY
	captureWidth := opts.Width

	// If selector is specified, find and crop to that element
	if opts.Selector != "" {
		node := doc.QuerySelector(opts.Selector)
		if node != nil {
			box := FindBoxByNode(layout.Root, node)
			if box != nil {
				captureX = box.X
				captureY = box.Y
				captureWidth = box.Width + box.PaddingLeft + box.PaddingRight +
					box.BorderLeft + box.BorderRight
				captureHeight = box.Height + box.PaddingTop + box.PaddingBottom +
					box.BorderTop + box.BorderBottom
				scrollY = 0 // no scroll offset for element capture
			}
		}
	}

	// Create image
	img := image.NewRGBA(image.Rect(0, 0, captureWidth, captureHeight))

	// Fill with body/html background color (like a real browser)
	bgColor := layout.BodyBg.BackgroundColor
	if bgColor.A == 0 {
		bgColor = color.RGBA{255, 255, 255, 255} // fallback to white
	}
	draw.Draw(img, img.Bounds(), &image.Uniform{bgColor}, image.Point{}, draw.Src)

	// Render layout boxes
	renderBox(img, layout.Root, captureX, captureY, captureWidth, captureHeight, doc)

	// Determine output path
	outPath := opts.Path
	isAutoPath := false
	if outPath == "" && doc.TempFiles != nil {
		outPath = doc.TempFiles.NextPath("")
		isAutoPath = true
	}
	if outPath == "" {
		outPath = filepath.Join("logs", "screenshot", "output.png")
		os.MkdirAll(filepath.Dir(outPath), 0755)
	}

	// Save PNG
	if err := savePNG(img, outPath); err != nil {
		return "", err
	}

	// Only track auto-generated paths for cleanup (not user-specified paths)
	if isAutoPath && doc.TempFiles != nil {
		doc.TempFiles.Track(outPath)
	}

	return outPath, nil
}

// renderBox recursively renders a layout box onto the image.
func renderBox(img *image.RGBA, box *LayoutBox, offsetX, offsetY, vpWidth, vpHeight int, doc *Document) {
	if box == nil {
		return
	}

	// Absolute position on the image
	imgX := box.X - offsetX
	imgY := box.Y - offsetY

	style := box.Style
	if style == nil {
		style = DefaultStyle("")
	}

	// Skip boxes entirely outside viewport
	totalBoxHeight := box.Height
	if imgY > vpHeight || imgY+totalBoxHeight < 0 {
		// Still render children as they might be in viewport
		for _, child := range box.Children {
			renderBox(img, child, offsetX, offsetY, vpWidth, vpHeight, doc)
		}
		return
	}

	// ── Border ──
	if style.BorderStyle != "none" && style.BorderStyle != "" {
		borderWidth := box.BorderTop
		if borderWidth > 0 {
			bx := imgX - box.BorderLeft
			by := imgY - box.BorderTop
			bw := box.Width + box.PaddingLeft + box.PaddingRight + box.BorderLeft + box.BorderRight
			bh := totalBoxHeight + box.BorderTop + box.BorderBottom
			drawRect(img, bx, by, bw, bh, style.BorderColor)
		}
	}

	// ── Background ──
	if style.BackgroundColor.A > 0 {
		bgX := imgX
		bgY := imgY
		bgW := box.Width + box.PaddingLeft + box.PaddingRight
		bgH := totalBoxHeight
		drawFilledRect(img, bgX, bgY, bgW, bgH, style.BackgroundColor)
	}

	// ── Text ──
	if box.IsText && box.Text != "" {
		textColor := style.Color
		fontSize := box.FontSize
		if fontSize == 0 {
			fontSize = 16
		}
		lh := lineHeightFromStyle(style)

		textWidth := box.Width
		if textWidth <= 0 {
			textWidth = vpWidth
		}
		lines := wrapText(box.Text, textWidth, fontSize)

		tx := imgX + box.PaddingLeft
		ty := imgY + box.PaddingTop

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				drawText(img, tx, ty, line, fontSize, textColor, style.FontWeight >= 700)
			}
			ty += lh
		}
	}

	// ── Image ──
	if box.IsImage && box.ImageSrc != "" && doc != nil && doc.Images != nil {
		src := ResolveURL(box.ImageSrc, doc.URL)
		if srcImg := doc.Images.Get(src); srcImg != nil {
			drawImage(img, srcImg, imgX, imgY, box.Width, box.Height)
		} else {
			// Draw placeholder rectangle for failed images
			placeholder := color.RGBA{220, 220, 220, 255}
			drawFilledRect(img, imgX, imgY, box.Width, box.Height, placeholder)
			borderC := color.RGBA{180, 180, 180, 255}
			drawRect(img, imgX, imgY, box.Width, box.Height, borderC)
			// Draw X in the center
			if box.Width > 20 && box.Height > 20 {
				drawText(img, imgX+4, imgY+4, "[img]", 10, color.RGBA{128, 128, 128, 255}, false)
			}
		}
	}

	// ── Children ──
	for _, child := range box.Children {
		renderBox(img, child, offsetX, offsetY, vpWidth, vpHeight, doc)
	}
}

// ──────────────────────────────────────────────
// Drawing primitives (pure Go, no external deps)
// ──────────────────────────────────────────────

// drawFilledRect fills a rectangle with a solid color.
func drawFilledRect(img *image.RGBA, x, y, w, h int, c color.RGBA) {
	bounds := img.Bounds()
	for py := y; py < y+h; py++ {
		if py < bounds.Min.Y || py >= bounds.Max.Y {
			continue
		}
		for px := x; px < x+w; px++ {
			if px < bounds.Min.X || px >= bounds.Max.X {
				continue
			}
			if c.A == 255 {
				img.SetRGBA(px, py, c)
			} else if c.A > 0 {
				blendPixel(img, px, py, c)
			}
		}
	}
}

// drawRect draws a rectangle outline (border).
func drawRect(img *image.RGBA, x, y, w, h int, c color.RGBA) {
	// Top
	drawFilledRect(img, x, y, w, 1, c)
	// Bottom
	drawFilledRect(img, x, y+h-1, w, 1, c)
	// Left
	drawFilledRect(img, x, y, 1, h, c)
	// Right
	drawFilledRect(img, x+w-1, y, 1, h, c)
}

// blendPixel does alpha-composite blending of a color onto a pixel.
func blendPixel(img *image.RGBA, x, y int, c color.RGBA) {
	existing := img.RGBAAt(x, y)
	alpha := uint16(c.A)
	invAlpha := 255 - alpha
	r := (uint16(c.R)*alpha + uint16(existing.R)*invAlpha) / 255
	g := (uint16(c.G)*alpha + uint16(existing.G)*invAlpha) / 255
	b := (uint16(c.B)*alpha + uint16(existing.B)*invAlpha) / 255
	a := uint16(c.A) + uint16(existing.A)*invAlpha/255
	img.SetRGBA(x, y, color.RGBA{uint8(r), uint8(g), uint8(b), uint8(a)})
}

// drawImage draws a source image onto the target, scaling to fit dstW×dstH.
func drawImage(dst *image.RGBA, src image.Image, dstX, dstY, dstW, dstH int) {
	if src == nil || dstW <= 0 || dstH <= 0 {
		return
	}
	bounds := src.Bounds()
	srcW := bounds.Dx()
	srcH := bounds.Dy()
	if srcW == 0 || srcH == 0 {
		return
	}

	dstBounds := dst.Bounds()

	// Nearest-neighbor scaling
	for py := 0; py < dstH; py++ {
		dy := dstY + py
		if dy < dstBounds.Min.Y || dy >= dstBounds.Max.Y {
			continue
		}
		sy := bounds.Min.Y + py*srcH/dstH
		for px := 0; px < dstW; px++ {
			dx := dstX + px
			if dx < dstBounds.Min.X || dx >= dstBounds.Max.X {
				continue
			}
			sx := bounds.Min.X + px*srcW/dstW
			r, g, b, a := src.At(sx, sy).RGBA()
			c := color.RGBA{uint8(r >> 8), uint8(g >> 8), uint8(b >> 8), uint8(a >> 8)}
			if c.A == 255 {
				dst.SetRGBA(dx, dy, c)
			} else if c.A > 0 {
				blendPixel(dst, dx, dy, c)
			}
		}
	}
}

// ──────────────────────────────────────────────
// Bitmap font renderer (built-in, no dependencies)
// ──────────────────────────────────────────────

// drawText renders text onto the image using a simple pixel-based approach.
// Characters are drawn as block-pixel glyphs scaled to fontSize.
func drawText(img *image.RGBA, x, y int, text string, fontSize int, c color.RGBA, bold bool) {
	// Scale: base glyph is 5×7 pixels, we scale to match fontSize
	scale := fontSize / 7
	if scale < 1 {
		scale = 1
	}
	glyphW := 5 * scale
	glyphH := 7 * scale
	spacing := scale // space between characters

	cx := x
	for _, ch := range text {
		glyph := getGlyph(ch)
		if glyph == nil {
			cx += glyphW + spacing
			continue
		}
		drawGlyph(img, cx, y, glyph, scale, c, bold)
		cx += glyphW + spacing
	}
	_ = glyphH // used for line height calculations in caller
}

// drawGlyph renders a single 5×7 bitmap glyph scaled to the given size.
func drawGlyph(img *image.RGBA, x, y int, glyph []string, scale int, c color.RGBA, bold bool) {
	bounds := img.Bounds()
	for row, line := range glyph {
		for col, ch := range line {
			if ch == '#' {
				for sy := 0; sy < scale; sy++ {
					for sx := 0; sx < scale; sx++ {
						px := x + col*scale + sx
						py := y + row*scale + sy
						if px >= bounds.Min.X && px < bounds.Max.X && py >= bounds.Min.Y && py < bounds.Max.Y {
							img.SetRGBA(px, py, c)
						}
					}
				}
				// Bold: draw one extra pixel right
				if bold {
					for sy := 0; sy < scale; sy++ {
						px := x + col*scale + scale
						py := y + row*scale + sy
						if px >= bounds.Min.X && px < bounds.Max.X && py >= bounds.Min.Y && py < bounds.Max.Y {
							img.SetRGBA(px, py, c)
						}
					}
				}
			}
		}
	}
}

// getGlyph returns a 5×7 bitmap for a character.
func getGlyph(ch rune) []string {
	if g, ok := glyphMap[ch]; ok {
		return g
	}
	// Fallback: lowercase → uppercase
	if ch >= 'a' && ch <= 'z' {
		if g, ok := glyphMap[ch-32]; ok {
			return g
		}
	}
	// Unknown character: empty box
	return glyphMap['?']
}

// savePNG writes an RGBA image to a PNG file.
func savePNG(img *image.RGBA, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

// ──────────────────────────────────────────────
// 5×7 Bitmap Glyphs (ASCII subset)
// ──────────────────────────────────────────────

var glyphMap = map[rune][]string{
	'A': {
		".###.",
		"#...#",
		"#...#",
		"#####",
		"#...#",
		"#...#",
		"#...#",
	},
	'B': {
		"####.",
		"#...#",
		"#...#",
		"####.",
		"#...#",
		"#...#",
		"####.",
	},
	'C': {
		".###.",
		"#...#",
		"#....",
		"#....",
		"#....",
		"#...#",
		".###.",
	},
	'D': {
		"####.",
		"#...#",
		"#...#",
		"#...#",
		"#...#",
		"#...#",
		"####.",
	},
	'E': {
		"#####",
		"#....",
		"#....",
		"###..",
		"#....",
		"#....",
		"#####",
	},
	'F': {
		"#####",
		"#....",
		"#....",
		"###..",
		"#....",
		"#....",
		"#....",
	},
	'G': {
		".###.",
		"#...#",
		"#....",
		"#.###",
		"#...#",
		"#...#",
		".###.",
	},
	'H': {
		"#...#",
		"#...#",
		"#...#",
		"#####",
		"#...#",
		"#...#",
		"#...#",
	},
	'I': {
		"#####",
		"..#..",
		"..#..",
		"..#..",
		"..#..",
		"..#..",
		"#####",
	},
	'J': {
		"..###",
		"...#.",
		"...#.",
		"...#.",
		"#..#.",
		"#..#.",
		".##..",
	},
	'K': {
		"#...#",
		"#..#.",
		"#.#..",
		"##...",
		"#.#..",
		"#..#.",
		"#...#",
	},
	'L': {
		"#....",
		"#....",
		"#....",
		"#....",
		"#....",
		"#....",
		"#####",
	},
	'M': {
		"#...#",
		"##.##",
		"#.#.#",
		"#...#",
		"#...#",
		"#...#",
		"#...#",
	},
	'N': {
		"#...#",
		"##..#",
		"#.#.#",
		"#..##",
		"#...#",
		"#...#",
		"#...#",
	},
	'O': {
		".###.",
		"#...#",
		"#...#",
		"#...#",
		"#...#",
		"#...#",
		".###.",
	},
	'P': {
		"####.",
		"#...#",
		"#...#",
		"####.",
		"#....",
		"#....",
		"#....",
	},
	'Q': {
		".###.",
		"#...#",
		"#...#",
		"#...#",
		"#.#.#",
		"#..#.",
		".##.#",
	},
	'R': {
		"####.",
		"#...#",
		"#...#",
		"####.",
		"#.#..",
		"#..#.",
		"#...#",
	},
	'S': {
		".###.",
		"#...#",
		"#....",
		".###.",
		"....#",
		"#...#",
		".###.",
	},
	'T': {
		"#####",
		"..#..",
		"..#..",
		"..#..",
		"..#..",
		"..#..",
		"..#..",
	},
	'U': {
		"#...#",
		"#...#",
		"#...#",
		"#...#",
		"#...#",
		"#...#",
		".###.",
	},
	'V': {
		"#...#",
		"#...#",
		"#...#",
		"#...#",
		".#.#.",
		".#.#.",
		"..#..",
	},
	'W': {
		"#...#",
		"#...#",
		"#...#",
		"#.#.#",
		"#.#.#",
		"##.##",
		"#...#",
	},
	'X': {
		"#...#",
		"#...#",
		".#.#.",
		"..#..",
		".#.#.",
		"#...#",
		"#...#",
	},
	'Y': {
		"#...#",
		"#...#",
		".#.#.",
		"..#..",
		"..#..",
		"..#..",
		"..#..",
	},
	'Z': {
		"#####",
		"....#",
		"...#.",
		"..#..",
		".#...",
		"#....",
		"#####",
	},
	'0': {
		".###.",
		"#..##",
		"#.#.#",
		"#.#.#",
		"#.#.#",
		"##..#",
		".###.",
	},
	'1': {
		"..#..",
		".##..",
		"..#..",
		"..#..",
		"..#..",
		"..#..",
		".###.",
	},
	'2': {
		".###.",
		"#...#",
		"....#",
		"..##.",
		".#...",
		"#....",
		"#####",
	},
	'3': {
		".###.",
		"#...#",
		"....#",
		"..##.",
		"....#",
		"#...#",
		".###.",
	},
	'4': {
		"...#.",
		"..##.",
		".#.#.",
		"#..#.",
		"#####",
		"...#.",
		"...#.",
	},
	'5': {
		"#####",
		"#....",
		"####.",
		"....#",
		"....#",
		"#...#",
		".###.",
	},
	'6': {
		".###.",
		"#....",
		"#....",
		"####.",
		"#...#",
		"#...#",
		".###.",
	},
	'7': {
		"#####",
		"....#",
		"...#.",
		"..#..",
		"..#..",
		"..#..",
		"..#..",
	},
	'8': {
		".###.",
		"#...#",
		"#...#",
		".###.",
		"#...#",
		"#...#",
		".###.",
	},
	'9': {
		".###.",
		"#...#",
		"#...#",
		".####",
		"....#",
		"....#",
		".###.",
	},
	' ': {
		".....",
		".....",
		".....",
		".....",
		".....",
		".....",
		".....",
	},
	'.': {
		".....",
		".....",
		".....",
		".....",
		".....",
		"..#..",
		"..#..",
	},
	',': {
		".....",
		".....",
		".....",
		".....",
		"..#..",
		"..#..",
		".#...",
	},
	':': {
		".....",
		"..#..",
		"..#..",
		".....",
		"..#..",
		"..#..",
		".....",
	},
	';': {
		".....",
		"..#..",
		"..#..",
		".....",
		"..#..",
		"..#..",
		".#...",
	},
	'!': {
		"..#..",
		"..#..",
		"..#..",
		"..#..",
		"..#..",
		".....",
		"..#..",
	},
	'?': {
		".###.",
		"#...#",
		"....#",
		"..##.",
		"..#..",
		".....",
		"..#..",
	},
	'-': {
		".....",
		".....",
		".....",
		"#####",
		".....",
		".....",
		".....",
	},
	'+': {
		".....",
		"..#..",
		"..#..",
		"#####",
		"..#..",
		"..#..",
		".....",
	},
	'=': {
		".....",
		".....",
		"#####",
		".....",
		"#####",
		".....",
		".....",
	},
	'(': {
		"...#.",
		"..#..",
		".#...",
		".#...",
		".#...",
		"..#..",
		"...#.",
	},
	')': {
		".#...",
		"..#..",
		"...#.",
		"...#.",
		"...#.",
		"..#..",
		".#...",
	},
	'[': {
		".###.",
		".#...",
		".#...",
		".#...",
		".#...",
		".#...",
		".###.",
	},
	']': {
		".###.",
		"...#.",
		"...#.",
		"...#.",
		"...#.",
		"...#.",
		".###.",
	},
	'/': {
		"....#",
		"...#.",
		"...#.",
		"..#..",
		".#...",
		".#...",
		"#....",
	},
	'\\': {
		"#....",
		".#...",
		".#...",
		"..#..",
		"...#.",
		"...#.",
		"....#",
	},
	'"': {
		".#.#.",
		".#.#.",
		".....",
		".....",
		".....",
		".....",
		".....",
	},
	'\'': {
		"..#..",
		"..#..",
		".....",
		".....",
		".....",
		".....",
		".....",
	},
	'<': {
		"...#.",
		"..#..",
		".#...",
		"#....",
		".#...",
		"..#..",
		"...#.",
	},
	'>': {
		".#...",
		"..#..",
		"...#.",
		"....#",
		"...#.",
		"..#..",
		".#...",
	},
	'#': {
		".#.#.",
		".#.#.",
		"#####",
		".#.#.",
		"#####",
		".#.#.",
		".#.#.",
	},
	'@': {
		".###.",
		"#...#",
		"#.###",
		"#.#.#",
		"#.##.",
		"#....",
		".####",
	},
	'_': {
		".....",
		".....",
		".....",
		".....",
		".....",
		".....",
		"#####",
	},
	'&': {
		".##..",
		"#..#.",
		".##..",
		".#...",
		"#.#.#",
		"#..#.",
		".##.#",
	},
	'*': {
		".....",
		"#.#.#",
		".###.",
		"#####",
		".###.",
		"#.#.#",
		".....",
	},
	'%': {
		"##..#",
		"##.#.",
		"..#..",
		"..#..",
		"..#..",
		".#.##",
		"#..##",
	},
	'{': {
		"..##.",
		".#...",
		".#...",
		"#....",
		".#...",
		".#...",
		"..##.",
	},
	'}': {
		".##..",
		"...#.",
		"...#.",
		"....#",
		"...#.",
		"...#.",
		".##..",
	},
}
