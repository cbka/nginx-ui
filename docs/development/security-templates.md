# Reusable security templates

Security templates capture website WAF/CrowdSec policy settings. They do not create
upstreams, TLS certificates, DNS records or complete application reverse proxies.
The existing Nginx configuration-template facility handles those distinct concerns.

Loading a profile creates an editable draft for the selected website. Review the
changes, validate/apply locally, then synchronize the saved policy to its configured
peers. A template is copied rather than linked: later template edits or deletion
do not silently alter existing websites. Custom profiles can capture deliberate
exceptions; recheck their path and parameter scope for each destination website.

## Application baselines

Built-in profiles are starting points, not vendor-certified WAF compatibility
packages. They do not supply guessed rule exclusions or automatically bypass
application endpoints. Test the application against the actual deployed CRS version
and use observed rule matches to create narrowly scoped exceptions when justified.

### Exchange on-premises

Verify the client services you expose, including Outlook on the web, Autodiscover,
EWS, ActiveSync and MAPI over HTTP. These are distinct application paths and should
remain functional after policy changes. See [Microsoft's Exchange load balancing
documentation](https://learn.microsoft.com/en-us/exchange/architecture/client-access/load-balancing).

TLS topology is separate from WAF policy. With Extended Protection, Microsoft does
not support SSL offloading to an unencrypted backend; supported SSL bridging requires
the same certificate at the load balancer and Exchange. This template does not alter
certificates or disable Extended Protection. See [Microsoft's Extended Protection
requirements](https://learn.microsoft.com/en-us/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/exchange-extended-protection).

### GitLab

Verify browser/API use, Git pushes, LFS transfers and artifact uploads. Buffering and
upload handling belong to the underlying proxy configuration, and GitLab's Registry,
Pages and KAS have separate service settings. A WAF template does not configure those
services. See [GitLab's Nginx configuration documentation](https://docs.gitlab.com/omnibus/settings/nginx/).
