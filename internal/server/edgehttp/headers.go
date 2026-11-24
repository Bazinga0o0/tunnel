package edgehttp

// IsForwardingHeader reports whether key names a header by which a proxy
// tells its backend about the client, in any spelling (isForwardingHeader).
// The proxy of the registered services drops them as the edge does.
func IsForwardingHeader(key string) bool { return isForwardingHeader(key) }
