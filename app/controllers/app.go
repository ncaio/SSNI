//
//
//
package controllers

//
//
//
import (
	"fmt"
	"github.com/likexian/whois-go"
	"github.com/revel/revel"
	_ "log"
	"net"
	"regexp"
	"strings"
)

//
//
//
type App struct {
	*revel.Controller
}

//
// Func lookup address / reverse
//
func lookup(address string) (resolv string) {
	r, _ := regexp.MatchString(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`, address)
	if r == true {
		addr, err := net.LookupAddr(address)
		if err != nil {
			fmt.Println("OPS !!! NOT FOUND !!!", address)
		} else {
			return addr[0]
		}
	} else {
		addr, err := net.LookupHost(address)
		if err != nil {
			fmt.Println("OPS !!! NOT FOUND !!!", address)
		} else {
			return addr[0]
		}
	}
	return
}

//
//
//
func (c App) Index() revel.Result {
	msg := "SSNI"
	org_name := "ORGANIZATION_NAME"
	return c.Render(msg, org_name)
}

//
//
//
func fwhois(host string) ([]string, string) {
	result, _ := whois.Whois(host, "whois.registro.br")
	line := strings.Split(result, "\n")
	var mail []string
	var domain string
	//
	//
	//
	for i := 0; i < len(line); i++ {
		if strings.HasPrefix(line[i], "e-mail:") {
			filtro := strings.Split(line[i], ":")
			email := strings.TrimSpace(filtro[1])
			mail = append(mail, email)
		} else if strings.HasPrefix(line[i], "domain:") {
			filtro := strings.Split(line[i], ":")
			domain = strings.TrimSpace(filtro[1])
		}
	}
	return mail, domain
}

//
//
//
func (c App) Desfiguracao(hostname string) revel.Result {
	c.Validation.Required(hostname).Message("Hostname is required!")
	c.Validation.MinSize(hostname, 5).Message("Your hostname is not long enough!")
	if c.Validation.HasErrors() {
		c.Validation.Keep()
		c.FlashParams()
		return c.Redirect(App.Index)
	}
	networkaddr := lookup(hostname)
	netcontact, _ := fwhois(networkaddr)
	netcontactlist := strings.Join(netcontact, ",")
	//
	//
	//
	domaincontact, _ := fwhois(hostname)
	domaincontactlist := strings.Join(domaincontact, ",")
	return c.Render(hostname, netcontactlist, domaincontactlist)
}

//
//
//
func (c App) Dominiosfraude(hostname string) revel.Result {
	domaincontact, domain := fwhois(hostname)
	domaincontactlist := strings.Join(domaincontact, ",")
	return c.Render(domaincontactlist, domain)
}

//
//
//
func (c App) Divulgadados(hostname string) revel.Result {
	ipaddr := lookup(hostname)
	netcontact, _ := fwhois(ipaddr)
	netcontactlist := strings.Join(netcontact, ",")
	return c.Render(hostname, ipaddr, netcontactlist)
}

//
//
//
func (c App) Ataquearede(hostname string) revel.Result {
	ipaddr := lookup(hostname)
	netcontact, _ := fwhois(ipaddr)
	netcontactlist := strings.Join(netcontact, ",")
	return c.Render(hostname, ipaddr, netcontactlist)
}

//
//
//
func (c App) Dnsmalicioso(hostname string) revel.Result {
	ipaddr := lookup(hostname)
	netcontact, _ := fwhois(ipaddr)
	netcontactlist := strings.Join(netcontact, ",")
	return c.Render(hostname, ipaddr, netcontactlist)
}

//
//
//
func (c App) Ddos(hostname string) revel.Result {
	ipaddr := lookup(hostname)
	netcontact, _ := fwhois(ipaddr)
	netcontactlist := strings.Join(netcontact, ",")
	return c.Render(hostname, ipaddr, netcontactlist)
}

//
//
//
func (c App) Drdos(hostname string) revel.Result {
	ipaddr := lookup(hostname)
	netcontact, _ := fwhois(ipaddr)
	netcontactlist := strings.Join(netcontact, ",")
	return c.Render(hostname, ipaddr, netcontactlist)
}

//
//
//
func (c App) Artefatos(hostname string) revel.Result {
	ipaddr := lookup(hostname)
	netcontact, _ := fwhois(ipaddr)
	netcontactlist := strings.Join(netcontact, ",")
	return c.Render(hostname, ipaddr, netcontactlist)
}

//
//
//
func (c App) Phishing(hostname string) revel.Result {
	ipaddr := lookup(hostname)
	netcontact, _ := fwhois(ipaddr)
	netcontactlist := strings.Join(netcontact, ",")
	return c.Render(hostname, ipaddr, netcontactlist)
}

//
//
//
func (c App) Phishingpharming(hostname string) revel.Result {
	ipaddr := lookup(hostname)
	netcontact, _ := fwhois(ipaddr)
	netcontactlist := strings.Join(netcontact, ",")
	return c.Render(hostname, ipaddr, netcontactlist)
}
