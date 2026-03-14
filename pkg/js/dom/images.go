package dom

import (
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ImageCache downloads and caches images for rendering.
type ImageCache struct {
	mu     sync.Mutex
	cache  map[string]image.Image
	client *http.Client
}

// NewImageCache creates an image cache with a timeout.
func NewImageCache() *ImageCache {
	return &ImageCache{
		cache: make(map[string]image.Image),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Get returns a cached image or downloads it.
func (ic *ImageCache) Get(rawURL string) image.Image {
	ic.mu.Lock()
	if img, ok := ic.cache[rawURL]; ok {
		ic.mu.Unlock()
		return img
	}
	ic.mu.Unlock()

	img := ic.download(rawURL)
	if img != nil {
		ic.mu.Lock()
		ic.cache[rawURL] = img
		ic.mu.Unlock()
	}
	return img
}

// Preload downloads multiple images concurrently.
func (ic *ImageCache) Preload(urls []string) {
	var wg sync.WaitGroup
	// Limit concurrency to 8
	sem := make(chan struct{}, 8)
	for _, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(rawURL string) {
			defer wg.Done()
			defer func() { <-sem }()
			ic.Get(rawURL)
		}(u)
	}
	wg.Wait()
}

func (ic *ImageCache) download(rawURL string) image.Image {
	if rawURL == "" {
		return nil
	}

	resp, err := ic.client.Get(rawURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	// Limit download to 10MB
	reader := io.LimitReader(resp.Body, 10*1024*1024)

	contentType := resp.Header.Get("Content-Type")
	img, err := decodeImage(reader, contentType, rawURL)
	if err != nil {
		return nil
	}
	return img
}

func decodeImage(r io.Reader, contentType string, rawURL string) (image.Image, error) {
	ct := strings.ToLower(contentType)

	// Try content-type first
	switch {
	case strings.Contains(ct, "png"):
		return png.Decode(r)
	case strings.Contains(ct, "jpeg") || strings.Contains(ct, "jpg"):
		return jpeg.Decode(r)
	case strings.Contains(ct, "gif"):
		return gif.Decode(r)
	}

	// Fallback: try by URL extension
	lower := strings.ToLower(rawURL)
	switch {
	case strings.HasSuffix(lower, ".png"):
		return png.Decode(r)
	case strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".jpeg"):
		return jpeg.Decode(r)
	case strings.HasSuffix(lower, ".gif"):
		return gif.Decode(r)
	}

	// Last resort: try all decoders via image.Decode
	img, _, err := image.Decode(r)
	return img, err
}

// ResolveURL resolves a potentially relative URL against a base URL.
func ResolveURL(src, baseURL string) string {
	if src == "" {
		return ""
	}

	// Already absolute
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return src
	}

	// Data URI — skip
	if strings.HasPrefix(src, "data:") {
		return ""
	}

	// Protocol-relative
	if strings.HasPrefix(src, "//") {
		return "https:" + src
	}

	if baseURL == "" {
		return src
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return src
	}

	ref, err := url.Parse(src)
	if err != nil {
		return src
	}

	return base.ResolveReference(ref).String()
}

// CollectImageURLs finds all <img> src attributes in the document.
func CollectImageURLs(doc *Document) []string {
	var urls []string
	imgs := doc.Root.GetElementsByTagName("img")
	for _, img := range imgs {
		src := img.GetAttribute("src")
		resolved := ResolveURL(src, doc.URL)
		if resolved != "" {
			urls = append(urls, resolved)
		}
	}
	return urls
}

// Clear empties the cache.
func (ic *ImageCache) Clear() {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.cache = make(map[string]image.Image)
}
