// Package logo renders the SysTeam wolf into terminal cells.
//
// Sixel and the Kitty graphics protocol are not usable here: tcell owns the
// screen and repaints it on every draw, and would immediately overwrite
// anything drawn outside its cell buffer. The approach that survives is
// textual — the upper half block '▀' with the upper pixel as foreground and
// the lower pixel as background, so one text row carries two pixel rows.
package logo

import (
	"bytes"
	_ "embed"
	"fmt"
	"image"
	"image/png"
	"sync"

	"github.com/gdamore/tcell/v2"
)

//go:embed assets/wolf.png
var logoPNG []byte

// Width and Height are the only cell size used. Measured against the asset:
// at 40x20 the ears, muzzle and ring all read; at 24x12 it is merely
// recognisable, and below about 16 columns it degrades to a blob.
const (
	Width  = 40
	Height = 20
)

// minColors is the colour count below which the neon gradients band badly
// enough that the ASCII banner is the better answer.
const minColors = 256

// minWidth is the terminal width below which the logo crowds out the panes.
const minWidth = 100

// Cell is one terminal cell of the rendered logo.
type Cell struct {
	Ch rune
	Fg tcell.Color
	Bg tcell.Color
}

// Viable reports whether the logo should be drawn at all, given the
// terminal's colour count and width. When it returns false the caller must
// fall back to the ASCII banner.
func Viable(colors, termWidth int) bool {
	return colors >= minColors && termWidth >= minWidth
}

type cacheKey struct {
	cols, rows int
	bg         tcell.Color
}

var (
	cacheMu sync.Mutex
	cache   = map[cacheKey][]Cell{}
)

// Cells renders the logo at cols x rows cells, compositing it over bg.
// The result is row-major and contains exactly cols*rows entries. Results
// are cached, so repeated draws at the same size cost one map lookup.
func Cells(cols, rows int, bg tcell.Color) ([]Cell, error) {
	if cols <= 0 || rows <= 0 {
		return nil, fmt.Errorf("logo: cell size must be positive, got %dx%d", cols, rows)
	}
	key := cacheKey{cols, rows, bg}

	cacheMu.Lock()
	defer cacheMu.Unlock()
	if got, ok := cache[key]; ok {
		return got, nil
	}

	src, err := png.Decode(bytes.NewReader(logoPNG))
	if err != nil {
		return nil, fmt.Errorf("logo: decode embedded asset: %w", err)
	}

	// Two pixel rows per text row.
	px := boxScale(src, cols, rows*2)

	br, bgg, bb := bg.RGB()
	out := make([]Cell, 0, cols*rows)
	for y := 0; y < rows; y++ {
		for x := 0; x < cols; x++ {
			top := px.over(x, 2*y, br, bgg, bb)
			bot := px.over(x, 2*y+1, br, bgg, bb)
			out = append(out, Cell{Ch: '▀', Fg: top, Bg: bot})
		}
	}
	cache[key] = out
	return out, nil
}

// rgba holds premultiplied 16-bit samples on a cols x rows grid.
type rgba struct {
	cols, rows int
	r, g, b, a []uint32
}

// over composites pixel (x, y) onto the given background and returns the
// resulting opaque colour. The stored samples are premultiplied, which is
// what src + dst*(1-alpha) expects.
func (p *rgba) over(x, y int, br, bg, bb int32) tcell.Color {
	i := y*p.cols + x
	inv := 0xffff - p.a[i]
	mix := func(s uint32, dst int32) int32 {
		// dst is 0..255, samples are 0..65535
		v := (s + uint32(dst)*257*inv/0xffff) / 257
		if v > 255 {
			v = 255
		}
		return int32(v)
	}
	return tcell.NewRGBColor(mix(p.r[i], br), mix(p.g[i], bg), mix(p.b[i], bb))
}

// boxScale downscales src to w x h by averaging every source pixel that
// falls inside each destination pixel.
//
// A box filter is the correct choice for minification: it is an exact area
// average, so it neither aliases nor rings. A cubic filter such as
// CatmullRom overshoots at high-contrast edges, which on this asset means
// haloes around every neon stroke. Writing the 30 lines here also avoids
// taking golang.org/x/image as a dependency for one call.
func boxScale(src image.Image, w, h int) *rgba {
	b := src.Bounds()
	out := &rgba{
		cols: w, rows: h,
		r: make([]uint32, w*h), g: make([]uint32, w*h),
		b: make([]uint32, w*h), a: make([]uint32, w*h),
	}
	for y := 0; y < h; y++ {
		y0 := b.Min.Y + y*b.Dy()/h
		y1 := b.Min.Y + (y+1)*b.Dy()/h
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < w; x++ {
			x0 := b.Min.X + x*b.Dx()/w
			x1 := b.Min.X + (x+1)*b.Dx()/w
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var sr, sg, sb, sa, n uint64
			for sy := y0; sy < y1; sy++ {
				for sx := x0; sx < x1; sx++ {
					cr, cg, cb, ca := src.At(sx, sy).RGBA()
					sr += uint64(cr)
					sg += uint64(cg)
					sb += uint64(cb)
					sa += uint64(ca)
					n++
				}
			}
			if n == 0 {
				n = 1
			}
			i := y*w + x
			out.r[i] = uint32(sr / n)
			out.g[i] = uint32(sg / n)
			out.b[i] = uint32(sb / n)
			out.a[i] = uint32(sa / n)
		}
	}
	return out
}
