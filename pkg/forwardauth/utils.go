package forwardauth

import (
	"fmt"
	"net/http"
)

func (fw *ForwardAuth) GetReturnUri(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	path := r.Header.Get("X-Forwarded-Uri")

	return fmt.Sprintf("%s://%s%s", proto, host, path)
}
