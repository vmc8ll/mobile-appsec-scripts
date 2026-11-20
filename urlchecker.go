package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	urlRe  = regexp.MustCompile(`(?i)\b((?:https?|ftps?|wss?|sftp|file)://[^\s"'<>\\]{3,})`)
	ipv4Re = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)`)
	ipv6Re = regexp.MustCompile(`(?i)(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,4}:(?:[0-9a-f]{1,4}:){1,3}[0-9a-f]{1,4})`)
)

type entry struct {
	Name string   `json:"name"`
	Size uint64   `json:"size"`
	URLs []string `json:"urls,omitempty"`
	IPv4 []string `json:"ipv4,omitempty"`
	IPv6 []string `json:"ipv6,omitempty"`
}

type summary struct {
	TotalURLs  int      `json:"total_urls"`
	TotalIPv4  int      `json:"total_ipv4"`
	TotalIPv6  int      `json:"total_ipv6"`
	URLs       []string `json:"urls"`
	IPv4       []string `json:"ipv4"`
	IPv6       []string `json:"ipv6"`
}

type report struct {
	File    string  `json:"file"`
	Entries []entry `json:"entries"`
	Summary summary `json:"summary"`
}

func isPrivate(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "127.") ||
		strings.HasPrefix(ip, "0.") || strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "169.254.") {
		return true
	}
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) > 1 {
			var second int
			fmt.Sscanf(parts[1], "%d", &second)
			if second >= 16 && second <= 31 {
				return true
			}
		}
	}
	return false
}

func extract(data []byte) (urls, ips4, ips6 []string) {
	urlSet := make(map[string]struct{})
	for _, m := range urlRe.FindAllSubmatch(data, -1) {
		urlSet[string(m[1])] = struct{}{}
	}
	ip4Set := make(map[string]struct{})
	for _, m := range ipv4Re.FindAll(data, -1) {
		ip4Set[string(m)] = struct{}{}
	}
	ip6Set := make(map[string]struct{})
	for _, m := range ipv6Re.FindAll(data, -1) {
		ip6Set[string(m)] = struct{}{}
	}

	for u := range urlSet {
		urls = append(urls, u)
	}
	for ip := range ip4Set {
		ips4 = append(ips4, ip)
	}
	for ip := range ip6Set {
		ips6 = append(ips6, ip)
	}
	sort.Strings(urls)
	sort.Strings(ips4)
	sort.Strings(ips6)
	return
}

func analyze(apkPath string, includePrivate bool) (*report, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	rep := &report{
		File:    apkPath,
		Entries: []entry{},
	}
	allURLs := make(map[string]struct{})
	allIP4 := make(map[string]struct{})
	allIP6 := make(map[string]struct{})

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if f.UncompressedSize64 > 200*1024*1024 {
			fmt.Fprintf(os.Stderr, "[i] skip (too large): %s\n", f.Name)
			continue
		}
		rc, err := f.Open()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] cannot open %s: %v\n", f.Name, err)
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] cannot read %s: %v\n", f.Name, err)
			continue
		}

		urls, ips4, ips6 := extract(data)
		if len(urls) == 0 && len(ips4) == 0 && len(ips6) == 0 {
			continue
		}

		rep.Entries = append(rep.Entries, entry{
			Name: f.Name,
			Size: f.UncompressedSize64,
			URLs: urls,
			IPv4: ips4,
			IPv6: ips6,
		})

		for _, u := range urls {
			allURLs[u] = struct{}{}
		}
		for _, ip := range ips4 {
			allIP4[ip] = struct{}{}
		}
		for _, ip := range ips6 {
			allIP6[ip] = struct{}{}
		}
	}

	if !includePrivate {
		for ip := range allIP4 {
			if isPrivate(ip) {
				delete(allIP4, ip)
			}
		}
	}

	rep.Summary.URLs = setToSorted(allURLs)
	rep.Summary.IPv4 = setToSorted(allIP4)
	rep.Summary.IPv6 = setToSorted(allIP6)
	rep.Summary.TotalURLs = len(rep.Summary.URLs)
	rep.Summary.TotalIPv4 = len(rep.Summary.IPv4)
	rep.Summary.TotalIPv6 = len(rep.Summary.IPv6)
	return rep, nil
}

func setToSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func main() {
	output := flag.String("o", "", "save JSON report to file")
	includePrivate := flag.Bool("include-private", false, "include private IPs")
	quiet := flag.Bool("quiet", false, "print summary only")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [options] file.apk\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	apkPath := flag.Arg(0)

	if _, err := os.Stat(apkPath); err != nil {
		fmt.Fprintf(os.Stderr, "file not found: %s\n", apkPath)
		os.Exit(1)
	}

	rep, err := analyze(apkPath, *includePrivate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== %s ===\n", filepath.Base(apkPath))
	fmt.Printf("URL:   %d\n", rep.Summary.TotalURLs)
	fmt.Printf("IPv4:  %d\n", rep.Summary.TotalIPv4)
	fmt.Printf("IPv6:  %d\n", rep.Summary.TotalIPv6)

	if !*quiet {
		if len(rep.Summary.URLs) > 0 {
			fmt.Println("\n--- URL ---")
			for _, u := range rep.Summary.URLs {
				fmt.Println(u)
			}
		}
		if len(rep.Summary.IPv4) > 0 {
			fmt.Println("\n--- IPv4 ---")
			for _, ip := range rep.Summary.IPv4 {
				fmt.Println(ip)
			}
		}
		if len(rep.Summary.IPv6) > 0 {
			fmt.Println("\n--- IPv6 ---")
			for _, ip := range rep.Summary.IPv6 {
				fmt.Println(ip)
			}
		}
	}

	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot create output: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(os.Stderr, "cannot write output: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n[+] report saved: %s\n", *output)
	}
}
