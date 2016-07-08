//
//
//
package controllers
//
//
//
import "github.com/revel/revel"
//
//
//
type App struct {
	*revel.Controller
}
//
//
//
func (c App) Index() revel.Result {
    msg:="SSNI"
	return c.Render(msg)
}
//
//
//
func (c App) Desfiguracao(hostname string) revel.Result{
c.Validation.Required(hostname).Message("Hostname is required!")
c.Validation.MinSize(hostname, 5).Message("Your hostname is not long enough!")
if c.Validation.HasErrors() {
    c.Validation.Keep()
    c.FlashParams()
    return c.Redirect(App.Index)
}
    return c.Render(hostname)
}
//
//
//
func (c App) Dominiosfraude(hostname string) revel.Result{
    return c.Render()
}
//
//
//
func (c App) Divulgadados(hostname string) revel.Result{
    return c.Render()
}
//
//
//
func (c App) Ataquearede(hostname string) revel.Result{
    return c.Render()
}
//
//
//
func (c App) Dnsmalicioso(hostname string) revel.Result{
    return c.Render()
}
//
//
//
func (c App) Ddos(hostname string) revel.Result{
    return c.Render()
}
//
//
//
func (c App) Drdos(hostname string) revel.Result{
    return c.Render()
}
