# LOCAL DEVELOPMENT ONLY. TLS is disabled; port publishing is loopback-only.
storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_disable     = true
}

api_addr = "http://127.0.0.1:8200"
ui = true
disable_mlock = true
