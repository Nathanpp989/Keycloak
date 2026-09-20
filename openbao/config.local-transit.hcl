# config.local-transit.hcl — MAIN OpenBao config for the LOCAL transit auto-unseal
# proof. Deliberately identical to the dev config.hcl EXCEPT it adds a transit
# seal, so the only variable under test is auto-unseal (storage + TLS stay as the
# dev setup). Used with BAO_AUTO_UNSEAL=1 via compose.transit.yaml.
#
# For production you swap this seal stanza for the azurekeyvault one in
# config.transit.hcl.example and (ideally) move to raft storage + listener TLS.

storage "file" {
  path = "/openbao/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr     = "http://openbao:8200"
cluster_addr = "http://openbao:8201"
disable_mlock = true
ui = false

# Auto-unseal via the local transit seal bao (compose service 'openbao-seal').
seal "transit" {
  address    = "http://openbao-seal:8200"
  token      = "sealroot"
  key_name   = "autounseal"
  mount_path = "transit/"
}
