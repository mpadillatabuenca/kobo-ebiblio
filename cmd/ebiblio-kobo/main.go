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
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
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
	N string `json:"n"`
	D string `json:"d"`
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
	WasCached     bool   `json:"-"`
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

func fulfillACSM(acsmBytes []byte) (*SyncedBook, error) {
	koboRoot := getKoboRoot()
	adeDir := filepath.Join(koboRoot, ".adobe-digital-editions")
	actPath := filepath.Join(adeDir, "activation.xml")
	devPath := filepath.Join(adeDir, "device.xml")

	actBytes, err := os.ReadFile(actPath)
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
	defer resp.Body.Close()
	replyBytes, _ := io.ReadAll(resp.Body)
	replyStr := string(replyBytes)

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

	// 2. Inject META-INF/rights.xml into EPUB zip
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
	for _, f := range zr.File {
		if f.Name == "META-INF/rights.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
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
	rw, err := zw.Create("META-INF/rights.xml")
	if err != nil {
		return nil, err
	}
	_, _ = rw.Write([]byte(rightsXML))
	_ = zw.Close()

	if err := writeFileSync(epubPath, outZipBuf.Bytes(), 0644); err != nil {
		return nil, err
	}

	// 3. Inject <loanToken> into activation.xml
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
	}

	return &SyncedBook{
		TransactionID: transactionID,
		Title:         title,
		Creator:       creator,
		Until:         untilStr,
		EpubFilename:  epubFilename,
		EpubPath:      epubPath,
		FulfillmentID: fulfillmentID,
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
	matches := reACSM.FindAllStringSubmatch(htmlLoans, -1)

	koboRoot := getKoboRoot()
	prevState := loadSyncedState()
	newState := make(map[string]*SyncedBook)
	activeTransactions := make(map[string]bool)

	seen := make(map[string]bool)
	var synced []*SyncedBook

	for _, m := range matches {
		href := html.UnescapeString(m[1])
		if strings.HasPrefix(href, "/") {
			href = com.URL + href
		}
		if seen[href] {
			continue
		}
		seen[href] = true

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
				if prev, ok := prevState[txID]; ok && prev.EpubFilename != "" {
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

			book, err := fulfillACSM(acsmData)
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
