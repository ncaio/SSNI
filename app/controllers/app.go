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
func (c App) Dominiosfraude() revel.Result{
    return c.Render()
}
//
//
//
func (c App) Divulgadados() revel.Result{
    return c.Render()
}
//
//
//
func (c App) Ataquearede() revel.Result{
    return c.Render()
}
//
//
//
func (c App) Dnsmalicioso() revel.Result{
    return c.Render()
}
//
//
//
func (c App) Ddos() revel.Result{
    return c.Render()
}
//
//
//
func (c App) Drdos() revel.Result{
    return c.Render()
}
