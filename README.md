# CertCrawler

## Get last release

Check how to get last release by your Operational Systems procedures here [INSTALL.md](https://github.com/helviojunior/certcrawler/blob/main/INSTALL.md)


# Utilization

```
$ certcrawler -h


_________                __   _________                      .__
\_   ___ \  ____________/  |_ \_   ___ \____________ __  _  _|  |   ___________
/    \  \/_/ __ \_  __ \   __\/    \  \/\_  __ \__  \\ \/ \/ /  | _/ __ \_  __ \
\     \___\  ___/|  | \/|  |  \     \____|  | \// __ \\     /|  |_\  ___/|  | \/
 \______  /\___  >__|   |__|   \______  /|__|  (____  /\/\_/ |____/\_____>__|
        \/     \/                     \/            \/           Ver: dev-dev

Usage:
  certcrawler [command]

Examples:

   - certcrawler crawler file -d sec4us.com.br -L /tmp/endpoint.txt -o certcrawler.txt
   - certcrawler crawler file -d /tmp/hostnames.txt -L /tmp/endpoint.txt --write-db

   - certcrawler crawler nmap -d sec4us.com.br -L /tmp/nmap.xml -o certcrawler.txt
   - certcrawler crawler nmap -d /tmp/hostnames.txt -L /tmp/nmap.xml --write-db

Available Commands:
  file        Perform SSL/TLS certificate crawler
  help        Help about any command
  version     Get the certcrawler version

Flags:
  -D, --debug-log                 Enable debug logging
  -h, --help                      help for certcrawler
      --log-scan-errors           Log scan errors (timeouts, DNS errors, etc.) to stderr (warning: can be verbose!)
  -X, --proxy string              Proxy to pass traffic through: <scheme://ip:port> (e.g., socks4://user:pass@proxy_host:1080
  -q, --quiet                     Silence (almost all) logging
  -t, --threads int               Number of concurrent threads (goroutines) to use (default 6)
  -T, --timeout int               Number of seconds before considering a page timed out (default 60)
      --write-csv                 Write results as CSV (has limited columns)
      --write-csv-file string     The file to write CSV rows to (default "certcrawler.csv")
      --write-db                  Write results to a SQLite database
      --write-db-enable-debug     Enable database query debug logging (warning: verbose!)
      --write-db-uri string       The database URI to use. Supports SQLite, Postgres, and MySQL (e.g., postgres://user:pass@host:port/db) (default "sqlite://certcrawler.sqlite3")
      --write-jsonl               Write results as JSON lines
      --write-jsonl-file string   The file to write JSON lines to (default "certcrawler.jsonl")
      --write-none                Use an empty writer to silence warnings
  -o, --write-text-file string    The file to write Text lines to

Additional help topics:
  certcrawler crawler Perform SSL/TLS certificate crawler

Use "certcrawler [command] --help" for more information about a command.

```


## Disclaimer

This tool is intended for educational purpose or for use in environments where you have been given explicit/legal authorization to do so.