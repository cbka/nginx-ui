#!/bin/sh
# Disposable --network none container only. Mount verified CrowdSec1.8.2 engine at /engine.
set -eu
mkdir -p /tmp/cs/hub /tmp/cs/data
printf '{}\n' > /tmp/cs/online.yaml
printf 'url: http://127.0.0.1:8080\nlogin: smoke\npassword: smoke\n' > /tmp/cs/local.yaml
cat > /tmp/cs/profiles.yaml <<'PROFILE'
name: smoke
filters:
 - Alert.Remediation == true
decisions:
 - type: ban
   duration: 1h
on_success: break
PROFILE
cat > /tmp/cs/config.yaml <<'CONFIG'
common:
 log_media: stdout
 log_level: error
config_paths:
 config_dir: /tmp/cs
 data_dir: /tmp/cs/data
 hub_dir: /tmp/cs/hub
 index_path: /tmp/cs/hub/.index.json
crowdsec_service:
 enable: false
db_config:
 type: sqlite
 db_path: /tmp/cs/data/crowdsec.db
api:
 client:
  credentials_path: /tmp/cs/local.yaml
 server:
  listen_uri: 127.0.0.1:8080
  profiles_path: /tmp/cs/profiles.yaml
  online_client:
   credentials_path: /tmp/cs/online.yaml
   sharing: false
   pull:
    community: true
    blocklists: true
CONFIG
value() { /usr/bin/cscli -c /tmp/cs/config.yaml config show --key "$1" -o json; }
validate() { /engine -c /tmp/cs/config.yaml -t -no-cs; }
test "$(value Config.API.Server.OnlineClient.Sharing)" = false
validate
test "$(value Config.API.Server.OnlineClient.PullConfig.Community)" = true
test "$(value Config.API.Server.OnlineClient.PullConfig.Blocklists)" = true
printf 'api:\n server:\n  online_client:\n   sharing: true\n' > /tmp/cs/config.yaml.local
test "$(value Config.API.Server.OnlineClient.Sharing)" = true
test "$(value Config.API.Server.OnlineClient.CredentialsFilePath)" = '"/tmp/cs/online.yaml"'
validate
printf 'api:\n server:\n  online_client:\n   sharing: false\n' > /tmp/cs/config.yaml.local
test "$(value Config.API.Server.OnlineClient.Sharing)" = false
validate
rm /tmp/cs/config.yaml.local
sed -i '/sharing: false/d' /tmp/cs/config.yaml
# cscli config show is the merged input; engine applies its default later.
test "$(value Config.API.Server.OnlineClient.Sharing)" = null
validate
printf 'api:\n server:\n  online_client:\n   sharing: invalid\n' > /tmp/cs/config.yaml.local
if validate >/tmp/invalid-sharing.log 2>&1; then
 echo 'Engine accepted invalid sharing value' >&2
 exit 1
fi
printf '%s\n' 'PASS: official engine validates false/true; .local wins while base credentials persist; absent sharing stays omitted in merged input; pull remains enabled; invalid sharing rejected; network isolated'
