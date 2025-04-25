package ascii

import (
	"fmt"
	"strings"
	"github.com/helviojunior/certcrawler/internal/version"
)

// Logo returns the certcrawler ascii logo
func Logo() string {
	txt := `                   

{O}_________                __   {G}_________                      .__                
{O}\_   ___ \  ____________/  |_ {G}\_   ___ \____________ __  _  _|  |   ___________ 
{O}/    \  \/_/ __ \_  __ \   __\{G}/    \  \/\_  __ \__  \\ \/ \/ /  | _/ __ \_  __ \
{O}\     \___\  ___/|  | \/|  |  {G}\     \____|  | \// __ \\     /|  |_\  ___/|  | \/
{O} \______  /\___  >__|   |__|  {G} \______  /|__|  (____  /\/\_/ |____/\_____>__|   
{O}        \/     \/             {G}        \/            \/{B}`

	v := fmt.Sprintf("Ver: %s-%s", version.Version, version.GitHash)
	txt += strings.Repeat(" ", 23 - len(v))
	txt += v + "{W}\n"
	txt = strings.Replace(txt, "{G}", "\033[32m", -1)
	txt = strings.Replace(txt, "{B}", "\033[36m", -1)
	txt = strings.Replace(txt, "{O}", "\033[33m", -1)
	txt = strings.Replace(txt, "{W}", "\033[0m", -1)
	return fmt.Sprintln(txt)
}

// LogoHelp returns the logo, with help
func LogoHelp(s string) string {
	return Logo() + "\n\n" + s
}
