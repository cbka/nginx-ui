package security_center

import "os"

// Config is deliberately environment-only: API callers cannot change
// executables or privileged filesystem paths.
type Config struct {
	AppSecEnabled                                                                             bool
	Enabled, CrowdSecEnabled, ModSecurityEnabled                                              bool
	CSCLIPath, NginxPath, ModSecurityPath, BaseConfig, CRSSetup, CRSRules, CrowdSecReloadPath string
	ControlURL, ControlTokenFile                                                              string
	SharingConfigPath, SharingValidatePath                                                    string
}

func EnvironmentConfig() Config {
	get := func(key, fallback string) string {
		if v := os.Getenv("SECURITY_CENTER_" + key); v != "" {
			return v
		}
		return fallback
	}
	return Config{
		AppSecEnabled: get("APPSEC_ENABLED", "false") == "true",
		Enabled:       get("ENABLED", "false") == "true", CrowdSecEnabled: get("CROWDSEC_ENABLED", "false") == "true", ModSecurityEnabled: get("MODSECURITY_ENABLED", "false") == "true",
		ControlURL: get("CONTROL_URL", ""), ControlTokenFile: get("CONTROL_TOKEN_FILE", ""),
		CSCLIPath: get("CSCLI_PATH", "/usr/bin/cscli"), NginxPath: get("NGINX_PATH", "/usr/sbin/nginx"), ModSecurityPath: get("MODSECURITY_PATH", "/etc/nginx/security-center/modsecurity.conf"), BaseConfig: get("BASE_CONFIG", "/etc/modsecurity/modsecurity.conf"), CRSSetup: get("CRS_SETUP", "/etc/modsecurity/crs/crs-setup.conf"), CRSRules: get("CRS_RULES", "/usr/share/modsecurity-crs/rules/*.conf"), CrowdSecReloadPath: get("CROWDSEC_RELOAD_PATH", ""), SharingConfigPath: get("SHARING_CONFIG_PATH", ""), SharingValidatePath: get("SHARING_VALIDATE_PATH", ""),
	}
}
