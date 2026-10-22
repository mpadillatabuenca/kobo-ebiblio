package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"html"
	"image"
	"image/color"
	"image/jpeg"
	_ "image/png"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Config struct {
	Comunidad   string `json:"comunidad"`
	EBiblioUser string `json:"ebiblio_user"`
	EBiblioPass string `json:"ebiblio_pass"`
}

type SigningKey struct {
	N    string `json:"n"`
	D    string `json:"d"`
	Cert string `json:"cert"`
}

type ComunidadInfo struct {
	Key  string
	Name string
	URL  string
}

var Comunidades = []ComunidadInfo{
	{"andalucia", "Andalucía", "https://andalucia.ebiblio.es"},
	{"aragon", "Aragón", "https://aragon.ebiblio.es"},
	{"asturias", "Asturias", "https://asturias.ebiblio.es"},
	{"baleares", "Illes Balears", "https://baleares.ebiblio.es"},
	{"canarias", "Canarias", "https://canarias.ebiblio.es"},
	{"cantabria", "Cantabria", "https://cantabria.ebiblio.es"},
	{"castillalamancha", "Castilla-La Mancha", "https://castillalamancha.ebiblio.es"},
	{"castillayleon", "Castilla y León", "https://castillayleon.ebiblio.es"},
	{"catalunya", "Cataluña", "https://catalunya.ebiblio.es"},
	{"ceuta", "Ceuta", "https://ceuta.ebiblio.es"},
	{"extremadura", "Extremadura", "https://extremadura.ebiblio.es"},
	{"galicia", "Galicia", "https://galicia.ebiblio.es"},
	{"larioja", "La Rioja", "https://larioja.ebiblio.es"},
	{"madrid", "Comunidad de Madrid", "https://madrid.ebiblio.es"},
	{"melilla", "Melilla", "https://melilla.ebiblio.es"},
	{"murcia", "Región de Murcia", "https://murcia.ebiblio.es"},
	{"navarra", "Navarra", "https://navarra.ebiblio.es"},
	{"euskadi", "País Vasco / Euskadi", "https://euskadi.ebiblio.es"},
	{"valencia", "Comunitat Valenciana", "https://valencia.ebiblio.es"},
}

func getComunidad(key string) ComunidadInfo {
	for _, c := range Comunidades {
		if c.Key == key {
			return c
		}
	}
	return Comunidades[0]
}

func getBaseDir() string {
	if _, err := os.Stat("/mnt/onboard/.adds/ebiblio"); err == nil {
		return "/mnt/onboard/.adds/ebiblio"
	}
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func getKoboRoot() string {
	if _, err := os.Stat("/mnt/onboard/.kobo"); err == nil {
		return "/mnt/onboard"
	}
	for _, d := range []string{"D:\\", "E:\\", "F:\\", "G:\\", "H:\\", "I:\\"} {
		if _, err := os.Stat(filepath.Join(d, ".kobo")); err == nil {
			return d
		}
	}
	return "."
}

func writeFileSync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if syncErr := f.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func loadConfig() Config {
	cfg := Config{Comunidad: "andalucia"}
	b, err := os.ReadFile(filepath.Join(getBaseDir(), "config.json"))
	if err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
	if cfg.Comunidad == "" {
		cfg.Comunidad = "andalucia"
	}
	return cfg
}

func buildNickelMenuConfig(cfg Config) string {
	com := getComunidad(cfg.Comunidad)
	return fmt.Sprintf(
		"# NickelMenu - Integracion eBiblio para Kobo\n"+
			"menu_item : main : Sincronizar eBiblio : nickel_wifi : autoconnect_silent\n"+
			"  chain_always : cmd_output : 9999 : quiet : /bin/sh /mnt/onboard/.adds/ebiblio/sync.sh\n"+
			"  chain_always : nickel_misc : rescan_books_full\n"+
			"menu_item : main : Catalogo Web (%s) : nickel_wifi : autoconnect\n"+
			"  chain_success : nickel_browser : modal : %s\n"+
			"menu_item : main : Ajustes eBiblio : nickel_wifi : autoconnect\n"+
			"  chain_success : cmd_output : 5000 : quiet : /bin/sh /mnt/onboard/.adds/ebiblio/start_ui.sh\n"+
			"  chain_success : nickel_browser : modal : http://127.0.0.1:8686/\n",
		com.Name, com.URL,
	)
}

func updateNickelMenuPortal(cfg Config) {
	nmPath := filepath.Join(getKoboRoot(), ".adds", "nm", "ebiblio")
	if _, err := os.Stat(nmPath); err != nil {
		return
	}
	_ = writeFileSync(nmPath, []byte(buildNickelMenuConfig(cfg)), 0644)
}

func saveConfig(cfg Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	err = writeFileSync(filepath.Join(getBaseDir(), "config.json"), b, 0600)
	updateNickelMenuPortal(cfg)
	return err
}

// =====================================================================
// Adobe ADEPT XML Canonical Hash & Pure-Go RSA Signature
// =====================================================================
const (
	ASN_NS_TAG    = 0x01
	ASN_CHILD     = 0x02
	ASN_END_TAG   = 0x03
	ASN_TEXT      = 0x04
	ASN_ATTRIBUTE = 0x05
	ADEPT_NS      = "http://ns.adobe.com/adept"
)

type xmlNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr `xml:",any,attr"`
	Children []xmlNode  `xml:",any"`
	Text     string     `xml:",chardata"`
}

func pushTag(h io.Writer, tag byte) {
	_, _ = h.Write([]byte{tag})
}

func pushString(h io.Writer, s string) {
	b := []byte(s)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(b)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(b)
}

func hashXMLNode(n xmlNode, h io.Writer) {
	if n.XMLName.Space != "" {
		pushTag(h, ASN_NS_TAG)
		pushString(h, n.XMLName.Space)
	}
	pushString(h, n.XMLName.Local)

	type attrItem struct {
		space, local, val string
	}
	var attrs []attrItem
	for _, a := range n.Attrs {
		if a.Name.Local == "xmlns" || a.Name.Space == "xmlns" || strings.HasPrefix(a.Name.Local, "xmlns:") {
			continue
		}
		attrs = append(attrs, attrItem{a.Name.Space, a.Name.Local, a.Value})
	}
	sort.Slice(attrs, func(i, j int) bool {
		return attrs[i].local < attrs[j].local
	})
	for _, a := range attrs {
		pushTag(h, ASN_ATTRIBUTE)
		pushString(h, a.space)
		pushString(h, a.local)
		pushString(h, a.val)
	}

	pushTag(h, ASN_CHILD)
	trimmed := strings.TrimSpace(n.Text)
	if trimmed != "" && len(n.Children) == 0 {
		pushTag(h, ASN_TEXT)
		pushString(h, trimmed)
	}
	for _, c := range n.Children {
		hashXMLNode(c, h)
	}
	pushTag(h, ASN_END_TAG)
}

func signXMLBytes(xmlData []byte) (string, error) {
	var root xmlNode
	if err := xml.Unmarshal(xmlData, &root); err != nil {
		return "", err
	}
	h := sha1.New()
	hashXMLNode(root, h)
	digest := h.Sum(nil)

	keyBytes, err := os.ReadFile(filepath.Join(getBaseDir(), "adobe_signing_key.json"))
	if err != nil {
		return "", fmt.Errorf("no se encontró adobe_signing_key.json: %w", err)
	}
	var sk SigningKey
	if err := json.Unmarshal(keyBytes, &sk); err != nil {
		return "", err
	}
	n := new(big.Int)
	d := new(big.Int)
	n.SetString(strings.TrimPrefix(sk.N, "0x"), 16)
	d.SetString(strings.TrimPrefix(sk.D, "0x"), 16)

	const kLen = 128
	padded := make([]byte, kLen)
	padded[0] = 0x00
	padded[1] = 0x01
	for i := 2; i < kLen-len(digest)-1; i++ {
		padded[i] = 0xff
	}
	padded[kLen-len(digest)-1] = 0x00
	copy(padded[kLen-len(digest):], digest)

	m := new(big.Int).SetBytes(padded)
	sigInt := new(big.Int).Exp(m, d, n)
	sigBytes := sigInt.Bytes()
	out := make([]byte, kLen)
	copy(out[kLen-len(sigBytes):], sigBytes)
	return base64.StdEncoding.EncodeToString(out), nil
}

func extractTag(xmlStr, tag string) string {
	re := regexp.MustCompile(`<(?:[a-zA-Z0-9_]+:)?` + regexp.QuoteMeta(tag) + `[^>]*>([^<]+)</(?:[a-zA-Z0-9_]+:)?` + regexp.QuoteMeta(tag) + `>`)
	m := re.FindStringSubmatch(xmlStr)
	if len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func extractBlock(xmlStr, tag string) string {
	re := regexp.MustCompile(`(?s)<(?:[a-zA-Z0-9_]+:)?` + regexp.QuoteMeta(tag) + `(?:\s[^>]*)?>.*?</(?:[a-zA-Z0-9_]+:)?` + regexp.QuoteMeta(tag) + `>`)
	return re.FindString(xmlStr)
}

func sanitizeFilename(name string) string {
	re := regexp.MustCompile(`[<>:"/\\|?*]`)
	s := strings.TrimSpace(re.ReplaceAllString(name, ""))
	if s == "" {
		return "Libro_eBiblio"
	}
	return s
}

type SyncedBook struct {
	TransactionID string `json:"transaction_id"`
	Title         string `json:"title"`
	Creator       string `json:"creator"`
	Until         string `json:"until"`
	EpubFilename  string `json:"epub_filename"`
	EpubPath      string `json:"epub_path"`
	FulfillmentID string `json:"fulfillment_id"`
	CoverUpdated  bool   `json:"cover_updated"`
	WasCached     bool   `json:"-"`
}

func koboQHash(s string) uint32 {
	var h uint32
	for _, b := range []byte(s) {
		h = (h << 4) + uint32(b)
		h ^= (h & 0xF0000000) >> 23
		h &= 0x0FFFFFFF
	}
	return h
}

func koboImageIDFromFilename(epubFilename string) string {
	contentID := "file:///mnt/onboard/Digital Editions/" + epubFilename
	r := strings.NewReplacer("/", "_", " ", "_", ":", "_", ".", "_")
	return r.Replace(contentID)
}

func koboCoverPaths(koboRoot, epubFilename string) (string, map[string][2]int) {
	imageID := koboImageIDFromFilename(epubFilename)
	h := koboQHash(imageID)
	dir1 := fmt.Sprintf("%d", h&0xFF)
	dir2 := fmt.Sprintf("%d", (h&0xFF00)>>8)
	basePath := filepath.Join(koboRoot, ".kobo-images", dir1, dir2, imageID)
	endings := map[string][2]int{
		" - N3_FULL.parsed":                      {1072, 1448},
		" - N3_LIBRARY_FULL.parsed":              {355, 530},
		" - N3_LIBRARY_GRID.parsed":              {149, 223},
		" - AndroidBookLoadTablet_Aspect.parsed": {355, 530},
	}
	return basePath, endings
}

func isNearWhite(c color.Color) bool {
	r, g, b, _ := c.RGBA()
	return (r>>8) >= 244 && (g>>8) >= 244 && (b>>8) >= 244
}

func trimWhiteBorders(src image.Image) image.Image {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w < 40 || h < 40 {
		return src
	}
	maxTrimX := w / 8
	maxTrimY := h / 8

	top := b.Min.Y
	for top < b.Min.Y+maxTrimY {
		whiteCount := 0
		for x := b.Min.X; x < b.Max.X; x++ {
			if isNearWhite(src.At(x, top)) {
				whiteCount++
			}
		}
		if whiteCount*100/w < 94 {
			break
		}
		top++
	}

	bottom := b.Max.Y - 1
	for bottom > b.Max.Y-1-maxTrimY && bottom > top {
		whiteCount := 0
		for x := b.Min.X; x < b.Max.X; x++ {
			if isNearWhite(src.At(x, bottom)) {
				whiteCount++
			}
		}
		if whiteCount*100/w < 94 {
			break
		}
		bottom--
	}

	left := b.Min.X
	for left < b.Min.X+maxTrimX {
		whiteCount := 0
		for y := top; y <= bottom; y++ {
			if isNearWhite(src.At(left, y)) {
				whiteCount++
			}
		}
		if whiteCount*100/(bottom-top+1) < 94 {
			break
		}
		left++
	}

	right := b.Max.X - 1
	for right > b.Max.X-1-maxTrimX && right > left {
		whiteCount := 0
		for y := top; y <= bottom; y++ {
			if isNearWhite(src.At(right, y)) {
				whiteCount++
			}
		}
		if whiteCount*100/(bottom-top+1) < 94 {
			break
		}
		right--
	}

	newW := right - left + 1
	newH := bottom - top + 1
	if newW <= 0 || newH <= 0 || (left == b.Min.X && right == b.Max.X-1 && top == b.Min.Y && bottom == b.Max.Y-1) {
		return src
	}
	dst := image.NewRGBA(image.Rect(0, 0, newW, newH))
	for y := 0; y < newH; y++ {
		for x := 0; x < newW; x++ {
			dst.Set(x, y, src.At(left+x, top+y))
		}
	}
	return dst
}

// resizeCoverFill scales src to fill dstW x dstH without white bars (center crop + bilinear interpolation).
func resizeCoverFill(src image.Image, dstW, dstH int) *image.RGBA {
	sb := src.Bounds()
	sw, sh := float64(sb.Dx()), float64(sb.Dy())
	dw, dh := float64(dstW), float64(dstH)

	scale := dw / sw
	if dh/sh > scale {
		scale = dh / sh
	}
	cropW := dw / scale
	cropH := dh / scale
	offX := float64(sb.Min.X) + (sw-cropW)/2.0
	offY := float64(sb.Min.Y) + (sh-cropH)/2.0

	dst := image.NewRGBA(image.Rect(0, 0, dstW, dstH))
	for y := 0; y < dstH; y++ {
		sy := offY + (float64(y)+0.5)*(cropH/dh) - 0.5
		y0 := int(sy)
		yf := sy - float64(y0)
		if y0 < sb.Min.Y {
			y0 = sb.Min.Y
			yf = 0
		}
		y1 := y0 + 1
		if y1 >= sb.Max.Y {
			y1 = sb.Max.Y - 1
		}

		for x := 0; x < dstW; x++ {
			sx := offX + (float64(x)+0.5)*(cropW/dw) - 0.5
			x0 := int(sx)
			xf := sx - float64(x0)
			if x0 < sb.Min.X {
				x0 = sb.Min.X
				xf = 0
			}
			x1 := x0 + 1
			if x1 >= sb.Max.X {
				x1 = sb.Max.X - 1
			}

			r00, g00, b00, _ := src.At(x0, y0).RGBA()
			r10, g10, b10, _ := src.At(x1, y0).RGBA()
			r01, g01, b01, _ := src.At(x0, y1).RGBA()
			r11, g11, b11, _ := src.At(x1, y1).RGBA()

			w00 := (1 - xf) * (1 - yf)
			w10 := xf * (1 - yf)
			w01 := (1 - xf) * yf
			w11 := xf * yf

			r := uint8((float64(r00>>8)*w00 + float64(r10>>8)*w10 + float64(r01>>8)*w01 + float64(r11>>8)*w11) + 0.5)
			g := uint8((float64(g00>>8)*w00 + float64(g10>>8)*w10 + float64(g01>>8)*w01 + float64(g11>>8)*w11) + 0.5)
			b := uint8((float64(b00>>8)*w00 + float64(b10>>8)*w10 + float64(b01>>8)*w01 + float64(b11>>8)*w11) + 0.5)

			dst.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
		}
	}
	return dst
}

func fetchBestCoverImage(title, creator, ebiblioCoverURL string) image.Image {
	coverClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 8 * time.Second,
	}
	tryDownload := func(u string) image.Image {
		if u == "" {
			return nil
		}
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return nil
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp, err := coverClient.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil || len(b) < 512 {
			return nil
		}
		img, _, err := image.Decode(bytes.NewReader(b))
		if err != nil {
			return nil
		}
		return trimWhiteBorders(img)
	}

	// 1. Try high-res cover from Apple Books ES (1000x1500, prioritizing Spanish ISBN 97884...)
	if title != "" {
		q := strings.TrimSpace(title + " " + creator)
		searchURL := "https://itunes.apple.com/search?term=" + url.QueryEscape(q) + "&entity=ebook&country=es&limit=5"
		req, err := http.NewRequest("GET", searchURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", "Mozilla/5.0")
			if resp, err := coverClient.Do(req); err == nil {
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				var parsed struct {
					Results []struct {
						ArtworkURL100 string `json:"artworkUrl100"`
					} `json:"results"`
				}
				if json.Unmarshal(b, &parsed) == nil && len(parsed.Results) > 0 {
					chosen := ""
					for _, r := range parsed.Results {
						if strings.Contains(r.ArtworkURL100, "/97884") {
							chosen = r.ArtworkURL100
							break
						}
					}
					if chosen == "" {
						chosen = parsed.Results[0].ArtworkURL100
					}
					if chosen != "" {
						hiURL := strings.Replace(chosen, "100x100bb", "1000x1500bb", 1)
						if img := tryDownload(hiURL); img != nil {
							return img
						}
					}
				}
			}
		}
	}

	// 2. Fallback to eBiblio's own cover URL
	if ebiblioCoverURL != "" {
		if strings.Contains(ebiblioCoverURL, "imagedelivery.net/") && strings.HasSuffix(ebiblioCoverURL, "/default") {
			largeURL := strings.TrimSuffix(ebiblioCoverURL, "/default") + "/large"
			if img := tryDownload(largeURL); img != nil {
				return img
			}
		}
		if img := tryDownload(ebiblioCoverURL); img != nil {
			return img
		}
	}
	return nil
}

func installKoboCachedCovers(koboRoot, epubFilename string, img image.Image) bool {
	if img == nil || epubFilename == "" {
		return false
	}
	basePath, endings := koboCoverPaths(koboRoot, epubFilename)
	_ = os.MkdirAll(filepath.Dir(basePath), 0755)
	okCount := 0
	for ending, dims := range endings {
		scaled := resizeCoverFill(img, dims[0], dims[1])
		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, scaled, &jpeg.Options{Quality: 92}); err == nil {
			if err := writeFileSync(basePath+ending, buf.Bytes(), 0644); err == nil {
				okCount++
			}
		}
	}
	return okCount > 0
}

func removeKoboCachedCovers(koboRoot, epubFilename string) {
	if epubFilename == "" {
		return
	}
	basePath, endings := koboCoverPaths(koboRoot, epubFilename)
	for ending := range endings {
		_ = os.Remove(basePath + ending)
	}
}

func patchOPFWithUnencryptedCover(opfStr string) string {
	reMetaCover := regexp.MustCompile(`(?i)<meta[^>]*name=["']cover["'][^>]*/?>`)
	opfStr = reMetaCover.ReplaceAllString(opfStr, "")
	rePropCover := regexp.MustCompile(`(?i)\s+properties=["']cover-image["']`)
	opfStr = rePropCover.ReplaceAllString(opfStr, "")

	opfStr = strings.Replace(opfStr, "</metadata>", `<meta name="cover" content="ebiblio_cover"/>`+"\n</metadata>", 1)
	opfStr = strings.Replace(opfStr, "</manifest>", `<item id="ebiblio_cover" href="ebiblio_cover.jpg" media-type="image/jpeg" properties="cover-image"/>`+"\n</manifest>", 1)
	return opfStr
}

func loadSyncedState() map[string]*SyncedBook {
	state := make(map[string]*SyncedBook)
	b, err := os.ReadFile(filepath.Join(getBaseDir(), "synced_state.json"))
	if err == nil {
		_ = json.Unmarshal(b, &state)
	}
	return state
}

func saveSyncedState(state map[string]*SyncedBook) {
	b, err := json.MarshalIndent(state, "", "  ")
	if err == nil {
		_ = writeFileSync(filepath.Join(getBaseDir(), "synced_state.json"), b, 0644)
	}
}

func newHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		Jar:       jar,
		Transport: tr,
		Timeout:   45 * time.Second,
	}
}

func makeADEPTNonce() string {
	var buf [12]byte
	ms := uint64(time.Now().UnixNano() / 1e6)
	n0 := uint32(0x6f046000) + uint32(ms&0xFFFFFFFF)
	n1 := uint32(0x0000388a) + uint32((ms>>32)&0xFFFFFFFF)
	binary.LittleEndian.PutUint32(buf[0:4], n0)
	binary.LittleEndian.PutUint32(buf[4:8], n1)
	binary.LittleEndian.PutUint32(buf[8:12], 0)
	return base64.StdEncoding.EncodeToString(buf[:])
}

func doOperatorAuth(client *http.Client, opURL, actStr string) error {
	keyBytes, err := os.ReadFile(filepath.Join(getBaseDir(), "adobe_signing_key.json"))
	if err != nil {
		return err
	}
	var sk SigningKey
	if err := json.Unmarshal(keyBytes, &sk); err != nil || sk.Cert == "" {
		return fmt.Errorf("adobe_signing_key.json no contiene el certificado 'cert'")
	}

	userUUID := extractTag(actStr, "user")
	licCert := extractTag(actStr, "licenseCertificate")
	authCert := extractTag(actStr, "authenticationCertificate")
	actURL := extractTag(actStr, "activationURL")
	if actURL == "" {
		actURL = "http://adeactivate.adobe.com/adept"
	}

	// 1. POST <operatorURL>/Auth
	authXML := fmt.Sprintf(
		`<?xml version="1.0"?>`+"\n"+
			`<adept:credentials xmlns:adept="http://ns.adobe.com/adept">`+
			`<adept:user>%s</adept:user>`+
			`<adept:certificate>%s</adept:certificate>`+
			`<adept:licenseCertificate>%s</adept:licenseCertificate>`+
			`<adept:authenticationCertificate>%s</adept:authenticationCertificate>`+
			`</adept:credentials>`,
		userUUID, sk.Cert, licCert, authCert,
	)
	req1, err := http.NewRequest("POST", opURL+"/Auth", bytes.NewReader([]byte(authXML)))
	if err != nil {
		return err
	}
	req1.Header.Set("Content-Type", "application/vnd.adobe.adept+xml")
	req1.Header.Set("User-Agent", "book2png")
	resp1, err := client.Do(req1)
	if err != nil {
		return err
	}
	_, _ = io.ReadAll(resp1.Body)
	resp1.Body.Close()

	// 2. POST <activationURL>/InitLicenseService
	expISO := time.Now().UTC().Add(10 * time.Minute).Format("2006-01-02T15:04:05Z")
	unsignedInit := fmt.Sprintf(
		`<adept:licenseServiceRequest xmlns:adept="http://ns.adobe.com/adept" identity="user">`+
			`<adept:operatorURL>%s</adept:operatorURL>`+
			`<adept:nonce>%s</adept:nonce>`+
			`<adept:expiration>%s</adept:expiration>`+
			`<adept:user>%s</adept:user>`+
			`</adept:licenseServiceRequest>`,
		opURL, makeADEPTNonce(), expISO, userUUID,
	)
	sigB64, err := signXMLBytes([]byte(unsignedInit))
	if err != nil {
		return err
	}
	signedInit := `<?xml version="1.0"?>` + "\n" + strings.Replace(unsignedInit, "</adept:licenseServiceRequest>", "<adept:signature>"+sigB64+"</adept:signature></adept:licenseServiceRequest>", 1)

	req2, err := http.NewRequest("POST", actURL+"/InitLicenseService", bytes.NewReader([]byte(signedInit)))
	if err != nil {
		return err
	}
	req2.Header.Set("Content-Type", "application/vnd.adobe.adept+xml")
	req2.Header.Set("User-Agent", "book2png")
	resp2, err := client.Do(req2)
	if err != nil {
		return err
	}
	_, _ = io.ReadAll(resp2.Body)
	resp2.Body.Close()
	return nil
}

func fulfillACSM(acsmBytes []byte, ebiblioCoverURL string) (*SyncedBook, error) {
	koboRoot := getKoboRoot()
	adeDir := filepath.Join(koboRoot, ".adobe-digital-editions")
	actPath := filepath.Join(adeDir, "activation.xml")
	devPath := filepath.Join(adeDir, "device.xml")
	actBackupPath := filepath.Join(koboRoot, ".adds", "ebiblio", "activation.backup.xml")

	actBytes, err := os.ReadFile(actPath)
	if err != nil || !bytes.Contains(actBytes, []byte("<activationInfo")) {
		if bkp, bErr := os.ReadFile(actBackupPath); bErr == nil && bytes.Contains(bkp, []byte("<activationInfo")) {
			actBytes = bkp
			_ = writeFileSync(actPath, actBytes, 0644)
			err = nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer %s: %w", actPath, err)
	}
	devBytes, err := os.ReadFile(devPath)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer %s: %w", devPath, err)
	}

	actStr := string(actBytes)
	devStr := string(devBytes)
	acsmStr := string(acsmBytes)

	transactionID := extractTag(acsmStr, "transaction")
	userUUID := extractTag(actStr, "user")
	actTokenBlock := extractBlock(actStr, "activationToken")
	deviceUUID := extractTag(actTokenBlock, "device")
	deviceType := extractTag(devStr, "deviceType")
	fingerprint := extractTag(devStr, "fingerprint")
	devClass := extractTag(devStr, "deviceClass")
	hobbesVer := "10.0.85385-DL.20140425"
	if m := regexp.MustCompile(`value="([^"]+)"`).FindStringSubmatch(devStr); len(m) > 1 {
		hobbesVer = m[1]
	}

	hmacVal := extractTag(acsmStr, "hmac")
	if hmacVal == "" {
		return nil, fmt.Errorf("ACSM inválido: sin hmac")
	}
	opURL := extractTag(acsmStr, "operatorURL")

	// Remove <hmac>...</hmac> from fulfillmentToken before signing
	reHmac := regexp.MustCompile(`(?s)\s*<hmac>.*?</hmac>\s*`)
	acsmNoHmac := reHmac.ReplaceAllString(acsmStr, "")
	acsmNoHmac = regexp.MustCompile(`<\?xml[^?]*\?>`).ReplaceAllString(acsmNoHmac, "")
	acsmNoHmac = strings.TrimSpace(acsmNoHmac)

	unsignedXML := fmt.Sprintf(
		`<adept:fulfill xmlns:adept="http://ns.adobe.com/adept">`+
			`<adept:user>%s</adept:user>`+
			`<adept:device>%s</adept:device>`+
			`<adept:deviceType>%s</adept:deviceType>`+
			`%s`+
			`<adept:targetDevice>`+
			`<adept:softwareVersion>%s</adept:softwareVersion>`+
			`<adept:clientOS>Linux 4.9.77</adept:clientOS>`+
			`<adept:clientLocale>es</adept:clientLocale>`+
			`<adept:clientVersion>%s</adept:clientVersion>`+
			`<adept:deviceType>%s</adept:deviceType>`+
			`<adept:fingerprint>%s</adept:fingerprint>`+
			`<adept:activationToken>`+
			`<adept:user>%s</adept:user>`+
			`<adept:device>%s</adept:device>`+
			`</adept:activationToken>`+
			`</adept:targetDevice>`+
			`</adept:fulfill>`,
		userUUID, deviceUUID, deviceType, acsmNoHmac,
		hobbesVer, devClass, deviceType, fingerprint,
		userUUID, deviceUUID,
	)

	sigB64, err := signXMLBytes([]byte(unsignedXML))
	if err != nil {
		return nil, fmt.Errorf("error firmando petición ACSM: %w", err)
	}

	// Restore hmac inside fulfillmentToken and add signature
	acsmWithHmac := strings.Replace(acsmNoHmac, "</fulfillmentToken>", "<hmac>"+hmacVal+"</hmac></fulfillmentToken>", 1)
	signedXML := `<?xml version="1.0"?>` + "\n" + strings.Replace(unsignedXML, acsmNoHmac, acsmWithHmac, 1)
	signedXML = strings.Replace(signedXML, "</adept:fulfill>", "<adept:signature>"+sigB64+"</adept:signature></adept:fulfill>", 1)

	client := newHTTPClient()
	req, err := http.NewRequest("POST", opURL+"/Fulfill", bytes.NewReader([]byte(signedXML)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/vnd.adobe.adept+xml")
	req.Header.Set("User-Agent", "book2png")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error conectando con %s/Fulfill: %w", opURL, err)
	}
	replyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	replyStr := string(replyBytes)

	if strings.Contains(replyStr, "E_LIC_USER_UNKNOWN") || strings.Contains(replyStr, "E_ADEPT_DISTRIBUTOR_AUTH") {
		if err := doOperatorAuth(client, opURL, actStr); err == nil {
			reqRetry, err := http.NewRequest("POST", opURL+"/Fulfill", bytes.NewReader([]byte(signedXML)))
			if err == nil {
				reqRetry.Header.Set("Content-Type", "application/vnd.adobe.adept+xml")
				reqRetry.Header.Set("User-Agent", "book2png")
				if respRetry, err := client.Do(reqRetry); err == nil {
					replyBytes, _ = io.ReadAll(respRetry.Body)
					respRetry.Body.Close()
					replyStr = string(replyBytes)
				}
			}
		}
	}

	if strings.Contains(replyStr, "<error ") {
		return nil, fmt.Errorf("servidor Adobe devolvió error: %s", replyStr)
	}

	srcURL := extractTag(replyStr, "src")
	if srcURL == "" {
		return nil, fmt.Errorf("respuesta Fulfill sin <src>")
	}
	licTokenBlock := extractBlock(replyStr, "licenseToken")
	loanTokenBlock := extractBlock(replyStr, "loanToken")

	title := html.UnescapeString(extractTag(replyStr, "title"))
	creator := html.UnescapeString(extractTag(replyStr, "creator"))
	untilStr := extractTag(licTokenBlock, "until")
	fulfillmentID := extractTag(licTokenBlock, "fulfillment")
	if title == "" {
		title = "Libro eBiblio"
	}

	licServiceInfo := extractBlock(actStr, "licenseServiceInfo")
	if licServiceInfo == "" {
		licURL := extractTag(licTokenBlock, "licenseURL")
		infoResp, err := client.Get(opURL + "/LicenseServiceInfo?licenseURL=" + url.QueryEscape(licURL))
		if err == nil {
			ib, _ := io.ReadAll(infoResp.Body)
			infoResp.Body.Close()
			cert := extractTag(string(ib), "certificate")
			licServiceInfo = fmt.Sprintf("<adept:licenseServiceInfo><adept:licenseURL>%s</adept:licenseURL><adept:certificate>%s</adept:certificate></adept:licenseServiceInfo>", licURL, cert)
		}
	}

	// 1. Download EPUB into Digital Editions
	deDir := filepath.Join(koboRoot, "Digital Editions")
	_ = os.MkdirAll(deDir, 0755)
	epubFilename := sanitizeFilename(title) + ".epub"
	epubPath := filepath.Join(deDir, epubFilename)

	epubReq, _ := http.NewRequest("GET", srcURL, nil)
	epubReq.Header.Set("User-Agent", "book2png")
	epubResp, err := client.Do(epubReq)
	if err != nil {
		return nil, fmt.Errorf("error descargando EPUB: %w", err)
	}
	epubBytes, err := io.ReadAll(epubResp.Body)
	epubResp.Body.Close()
	if err != nil {
		return nil, err
	}

	// 2. Fetch clean HD cover (Apple Books ES 1000x1500 -> eBiblio cover fallback)
	coverImg := fetchBestCoverImage(title, creator, ebiblioCoverURL)
	var coverJPEGBytes []byte
	if coverImg != nil {
		scaled := resizeCoverFill(coverImg, 710, 1060)
		var cbuf bytes.Buffer
		if err := jpeg.Encode(&cbuf, scaled, &jpeg.Options{Quality: 92}); err == nil {
			coverJPEGBytes = cbuf.Bytes()
		}
	}

	// 3. Inject META-INF/rights.xml and unencrypted ebiblio_cover.jpg into EPUB zip
	if !strings.Contains(licTokenBlock, "xmlns=") {
		licTokenBlock = strings.Replace(licTokenBlock, "<licenseToken>", `<licenseToken xmlns="http://ns.adobe.com/adept">`, 1)
	}
	rightsXML := fmt.Sprintf(`<?xml version="1.0"?><adept:rights xmlns:adept="http://ns.adobe.com/adept">%s%s</adept:rights>`, licTokenBlock, licServiceInfo)

	zr, err := zip.NewReader(bytes.NewReader(epubBytes), int64(len(epubBytes)))
	if err != nil {
		return nil, fmt.Errorf("archivo descargado no es un EPUB válido: %w", err)
	}
	var outZipBuf bytes.Buffer
	zw := zip.NewWriter(&outZipBuf)
	opfDir := ""
	for _, f := range zr.File {
		if f.Name == "META-INF/rights.xml" || strings.HasSuffix(f.Name, "ebiblio_cover.jpg") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		if len(coverJPEGBytes) > 0 && strings.HasSuffix(strings.ToLower(f.Name), ".opf") {
			opfBytes, _ := io.ReadAll(rc)
			rc.Close()
			opfDir = path.Dir(f.Name)
			patchedOPF := patchOPFWithUnencryptedCover(string(opfBytes))
			w, err := zw.Create(f.Name)
			if err != nil {
				return nil, err
			}
			_, _ = w.Write([]byte(patchedOPF))
			continue
		}
		hdr := f.FileHeader
		w, err := zw.CreateHeader(&hdr)
		if err != nil {
			rc.Close()
			return nil, err
		}
		_, _ = io.Copy(w, rc)
		rc.Close()
	}
	if len(coverJPEGBytes) > 0 {
		coverEntryName := "ebiblio_cover.jpg"
		if opfDir != "" && opfDir != "." {
			coverEntryName = opfDir + "/ebiblio_cover.jpg"
		}
		if cw, err := zw.Create(coverEntryName); err == nil {
			_, _ = cw.Write(coverJPEGBytes)
		}
	}
	rw, err := zw.Create("META-INF/rights.xml")
	if err != nil {
		return nil, err
	}
	_, _ = rw.Write([]byte(rightsXML))
	_ = zw.Close()

	if err := writeFileSync(epubPath, outZipBuf.Bytes(), 0644); err != nil {
		return nil, err
	}

	// 4. Write KEPUB-style borderless thumbnails directly into .kobo-images
	coverUpdated := installKoboCachedCovers(koboRoot, epubFilename, coverImg)

	// 5. Inject <loanToken> into activation.xml
	if loanTokenBlock != "" {
		loanID := extractTag(loanTokenBlock, "loan")
		if loanID != "" {
			reOldLoan := regexp.MustCompile(`(?s)<loanToken>.*?<loan>` + regexp.QuoteMeta(loanID) + `</loan>.*?</loanToken>`)
			actStr = reOldLoan.ReplaceAllString(actStr, "")
		}
		if strings.Contains(actStr, "<adept:licenseServices") {
			actStr = strings.Replace(actStr, "<adept:licenseServices", loanTokenBlock+"<adept:licenseServices", 1)
		} else {
			licServices := fmt.Sprintf(`<adept:licenseServices xmlns:adept="http://ns.adobe.com/adept">%s</adept:licenseServices>`, licServiceInfo)
			actStr = strings.Replace(actStr, "</activationInfo>", loanTokenBlock+licServices+"</activationInfo>", 1)
		}
		_ = writeFileSync(actPath, []byte(actStr), 0644)
		_ = writeFileSync(actBackupPath, []byte(actStr), 0644)
	}

	return &SyncedBook{
		TransactionID: transactionID,
		Title:         title,
		Creator:       creator,
		Until:         untilStr,
		EpubFilename:  epubFilename,
		EpubPath:      epubPath,
		FulfillmentID: fulfillmentID,
		CoverUpdated:  coverUpdated,
	}, nil
}

func syncEBiblioLoans(cfg Config) ([]*SyncedBook, int, error) {
	com := getComunidad(cfg.Comunidad)
	if cfg.EBiblioUser == "" || cfg.EBiblioPass == "" {
		return nil, 0, fmt.Errorf("configura primero tu usuario y contraseña de eBiblio en Ajustes")
	}

	client := newHTTPClient()
	signInURL := com.URL + "/ebiblio_auth_sign_in"

	resp, err := client.Get(signInURL)
	if err != nil {
		return nil, 0, fmt.Errorf("no se pudo conectar con %s (comprueba el Wi-Fi): %w", com.Name, err)
	}
	body1, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	mTok := regexp.MustCompile(`name="authenticity_token"\s+value="([^"]+)"`).FindStringSubmatch(string(body1))
	if len(mTok) < 2 {
		return nil, 0, fmt.Errorf("no se encontró authenticity_token en %s", signInURL)
	}

	vals := url.Values{
		"authenticity_token": {mTok[1]},
		"login":              {cfg.EBiblioUser},
		"password":           {cfg.EBiblioPass},
		"remember_me":        {"1"},
		"button":             {""},
	}
	reqPost, _ := http.NewRequest("POST", signInURL, strings.NewReader(vals.Encode()))
	reqPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqPost.Header.Set("Origin", com.URL)
	reqPost.Header.Set("Referer", signInURL)

	resp2, err := client.Do(reqPost)
	if err != nil {
		return nil, 0, fmt.Errorf("error enviando login a eBiblio: %w", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if strings.Contains(string(body2), `id="form-authentication"`) {
		return nil, 0, fmt.Errorf("usuario o contraseña de eBiblio incorrectos (%s)", com.Name)
	}

	// Fetch /my_profile/activity
	resp3, err := client.Get(com.URL + "/my_profile/activity")
	if err != nil {
		return nil, 0, fmt.Errorf("error consultando préstamos activos: %w", err)
	}
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	htmlLoans := string(body3)

	reACSM := regexp.MustCompile(`href=["']([^"']*drm=acs4[^"']*)["']`)
	reCover := regexp.MustCompile(`<img[^>]*class=["'][^"']*cover[^"']*["'][^>]*src=["']([^"']+)["']`)
	matchIndices := reACSM.FindAllStringSubmatchIndex(htmlLoans, -1)

	koboRoot := getKoboRoot()
	prevState := loadSyncedState()
	newState := make(map[string]*SyncedBook)
	activeTransactions := make(map[string]bool)

	seen := make(map[string]bool)
	var synced []*SyncedBook

	for _, idx := range matchIndices {
		href := html.UnescapeString(htmlLoans[idx[2]:idx[3]])
		if strings.HasPrefix(href, "/") {
			href = com.URL + href
		}
		if seen[href] {
			continue
		}
		seen[href] = true

		// Find nearest preceding cover <img> in this loan card
		ebiblioCoverURL := ""
		coverMatches := reCover.FindAllStringSubmatch(htmlLoans[:idx[0]], -1)
		if len(coverMatches) > 0 {
			ebiblioCoverURL = html.UnescapeString(coverMatches[len(coverMatches)-1][1])
			if strings.HasPrefix(ebiblioCoverURL, "/") {
				ebiblioCoverURL = com.URL + ebiblioCoverURL
			}
		}

		acsmResp, err := client.Get(href)
		if err != nil {
			continue
		}
		acsmData, _ := io.ReadAll(acsmResp.Body)
		acsmResp.Body.Close()

		if bytes.Contains(acsmData, []byte("<fulfillmentToken")) {
			txID := extractTag(string(acsmData), "transaction")
			if txID != "" {
				activeTransactions[txID] = true
				if prev, ok := prevState[txID]; ok && prev.EpubFilename != "" && prev.CoverUpdated {
					expectedPath := filepath.Join(koboRoot, "Digital Editions", prev.EpubFilename)
					if _, err := os.Stat(expectedPath); err == nil {
						prev.EpubPath = expectedPath
						prev.WasCached = true
						synced = append(synced, prev)
						newState[txID] = prev
						continue
					}
				}
			}

			book, err := fulfillACSM(acsmData, ebiblioCoverURL)
			if err != nil {
				return synced, 0, err
			}
			synced = append(synced, book)
			if book.TransactionID != "" {
				newState[book.TransactionID] = book
			}
		}
	}

	// Clean up returned or expired loans that were previously managed by kobo-ebiblio
	removedCount := 0
	for txID, oldBook := range prevState {
		if !activeTransactions[txID] && oldBook.EpubFilename != "" {
			oldPath := filepath.Join(koboRoot, "Digital Editions", oldBook.EpubFilename)
			if err := os.Remove(oldPath); err == nil {
				removedCount++
			}
			removeKoboCachedCovers(koboRoot, oldBook.EpubFilename)
		}
	}

	saveSyncedState(newState)
	return synced, removedCount, nil
}

const pageHTML = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ajustes eBiblio para Kobo</title>
<style>
  * { box-sizing: border-box; font-family: Georgia, serif; }
  body { margin: 0; padding: 16px; background: #fff; color: #000; max-width: 680px; margin-left: auto; margin-right: auto; }
  h1 { font-size: 24px; margin: 0 0 6px 0; border-bottom: 3px solid #000; padding-bottom: 8px; }
  .sub { font-size: 14px; margin-bottom: 16px; color: #222; }
  .card { border: 2px solid #000; padding: 14px; margin-bottom: 16px; background: #fff; }
  .card h2 { font-size: 18px; margin: 0 0 12px 0; border-bottom: 1px solid #000; padding-bottom: 6px; }
  label { display: block; font-weight: bold; margin-bottom: 4px; font-size: 15px; }
  select, input[type="text"], input[type="password"] {
    width: 100%; padding: 10px; font-size: 16px; border: 2px solid #000; background: #fff; color: #000; margin-bottom: 12px;
  }
  .btn {
    display: inline-block; width: 100%; padding: 12px; font-size: 17px; font-weight: bold;
    text-align: center; background: #000; color: #fff; border: 2px solid #000; cursor: pointer;
    text-decoration: none; margin-bottom: 8px;
  }
  .btn-secondary { background: #fff; color: #000; }
  .status { border: 2px solid #000; padding: 12px; margin-bottom: 16px; background: #f4f4f4; font-size: 15px; }
</style>
</head>
<body>
  <h1>eBiblio para Kobo</h1>
  <div class="sub">Kobo detectado: <strong>{{KOBO_ROOT}}</strong></div>

  {{STATUS_BLOCK}}

  <div class="card">
    <h2>Configuración y Sincronización de eBiblio</h2>
    <form method="POST" action="/sync">
      <label for="comunidad">Comunidad Autónoma:</label>
      <select name="comunidad" id="comunidad">
        {{OPTIONS}}
      </select>

      <label for="ebiblio_user">Correo electrónico / Usuario eBiblio:</label>
      <input type="text" name="ebiblio_user" id="ebiblio_user" value="{{USER}}" placeholder="tu-correo@ejemplo.com" required>

      <label for="ebiblio_pass">Contraseña eBiblio:</label>
      <input type="password" name="ebiblio_pass" id="ebiblio_pass" value="{{PASS}}" placeholder="••••••••" required>

      <button type="submit" class="btn">Guardar y Sincronizar Mis Préstamos Ahora</button>
    </form>
    <a class="btn btn-secondary" href="{{PORTAL_URL}}">Ir al Catálogo Web de {{COMUNIDAD_NAME}}</a>
  </div>
</body>
</html>`

var lastActivity = time.Now()

func sendHTML(w http.ResponseWriter, htmlStr string) {
	lastActivity = time.Now()
	outBytes := []byte(htmlStr)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(outBytes)))
	w.Header().Set("Connection", "close")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(outBytes)
}

func renderUI(w http.ResponseWriter, statusMsg string) {
	cfg := loadConfig()
	com := getComunidad(cfg.Comunidad)

	var opts strings.Builder
	for _, c := range Comunidades {
		sel := ""
		if c.Key == cfg.Comunidad {
			sel = "selected"
		}
		host := strings.TrimPrefix(c.URL, "https://")
		fmt.Fprintf(&opts, `<option value="%s" %s>%s (%s)</option>`, c.Key, sel, html.EscapeString(c.Name), host)
	}

	statusBlock := ""
	if statusMsg != "" {
		statusBlock = `<div class="status">` + statusMsg + `</div>`
	}

	out := pageHTML
	out = strings.ReplaceAll(out, "{{KOBO_ROOT}}", html.EscapeString(getKoboRoot()))
	out = strings.ReplaceAll(out, "{{STATUS_BLOCK}}", statusBlock)
	out = strings.ReplaceAll(out, "{{OPTIONS}}", opts.String())
	out = strings.ReplaceAll(out, "{{USER}}", html.EscapeString(cfg.EBiblioUser))
	out = strings.ReplaceAll(out, "{{PASS}}", html.EscapeString(cfg.EBiblioPass))
	out = strings.ReplaceAll(out, "{{PORTAL_URL}}", com.URL)
	out = strings.ReplaceAll(out, "{{COMUNIDAD_NAME}}", html.EscapeString(com.Name))

	sendHTML(w, out)
}

func main() {
	_ = rand.Reader
	syncFlag := flag.Bool("sync", false, "Sincronizar préstamos activos por CLI")
	addrFlag := flag.String("addr", "127.0.0.1:8686", "Dirección del servidor web local")
	flag.Parse()

	if *syncFlag {
		cfg := loadConfig()
		books, removed, err := syncEBiblioLoans(cfg)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if len(books) == 0 {
			if removed > 0 {
				fmt.Printf("No tienes préstamos activos (se limpiaron %d préstamo(s) vencidos/devueltos).\n", removed)
			} else {
				fmt.Println("No hay préstamos activos pendientes en tu cuenta de eBiblio.")
			}
			return
		}
		newCount := 0
		for _, b := range books {
			if !b.WasCached {
				newCount++
			}
		}
		fmt.Printf("¡Préstamos de eBiblio al día! (%d activos, %d nuevos descargados", len(books), newCount)
		if removed > 0 {
			fmt.Printf(", %d caducados limpiados", removed)
		}
		fmt.Println("):")
		for _, b := range books {
			tag := "nuevo"
			if b.WasCached {
				tag = "ya en el Kobo"
			}
			fmt.Printf("• %s (%s) [%s]\n", b.Title, b.Creator, tag)
		}
		return
	}

	// Auto-shutdown after 10 minutes of inactivity on Kobo so battery is never drained
	go func() {
		for {
			time.Sleep(30 * time.Second)
			if time.Since(lastActivity) > 10*time.Minute {
				os.Exit(0)
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		renderUI(w, "")
	})

	mux.HandleFunc("/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		_ = r.ParseForm()
		cfg := loadConfig()
		cfg.Comunidad = strings.TrimSpace(r.FormValue("comunidad"))
		cfg.EBiblioUser = strings.TrimSpace(r.FormValue("ebiblio_user"))
		cfg.EBiblioPass = r.FormValue("ebiblio_pass")
		_ = saveConfig(cfg)

		books, removed, err := syncEBiblioLoans(cfg)
		if err != nil {
			renderUI(w, "<strong>Error al sincronizar:</strong> "+html.EscapeString(err.Error()))
			return
		}
		if len(books) == 0 {
			msg := "Conectado correctamente. No tienes préstamos activos con DRM Adobe en este momento."
			if removed > 0 {
				msg += fmt.Sprintf(" (Se han limpiado %d préstamo(s) devueltos/vencidos).", removed)
			}
			renderUI(w, msg)
			return
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "<strong>¡Sincronizados %d préstamo(s) en tu Kobo!</strong><ul>", len(books))
		for _, b := range books {
			fmt.Fprintf(&sb, "<li><strong>%s</strong> (%s) — Válido hasta: %s</li>",
				html.EscapeString(b.Title), html.EscapeString(b.Creator), html.EscapeString(b.Until))
		}
		sb.WriteString("</ul>")
		if removed > 0 {
			fmt.Fprintf(&sb, "<p>Se limpiaron %d préstamo(s) devueltos o caducados.</p>", removed)
		}
		renderUI(w, sb.String())
	})

	srv := &http.Server{
		Addr:    *addrFlag,
		Handler: mux,
	}
	srv.SetKeepAlivesEnabled(false)
	fmt.Printf("Servidor Kobo eBiblio escuchando en http://%s\n", *addrFlag)
	_ = srv.ListenAndServe()
}
