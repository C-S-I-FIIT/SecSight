path "kv/*" {
  capabilities = ["read", "list"]
}

# If you're using KV v2, use this path instead:
# path "kv/data/*" {
#   capabilities = ["read", "list"]
# } 