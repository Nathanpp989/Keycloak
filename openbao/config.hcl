# Persistent OpenBao configuration (replaces `-dev` mode).
# File storage on a mounted volume so data — including the PKI CA — survives
# container restarts. TLS is disabled on the listener because Traefik terminates
# TLS in front of OpenBao (routed as openbao.localhost / openbao.test.local);
# inside the compose network the hop is plain HTTP.
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
