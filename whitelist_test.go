package whitelist

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mailgun/vulcand/plugin"
)

func TestAdheresToVulcandMiddlewareSpec(t *testing.T) {
	result := plugin.NewRegistry().AddSpec(GetSpec())
	if result != nil {
		t.Errorf("spec is not ok - addspec returned %s", result)
	}
}

func TestWhitelistHandlerRejectsRequests(t *testing.T) {
	ranges := []ipRange{
		newIPRange(net.ParseIP("51.1.1.0"), net.ParseIP("51.1.1.10")),
	}

	handler := &WhitelistHandler{allowedRanges: ranges}

	resp := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "201.11.14.1:11222"

	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Errorf("expected 403, but got %s", resp.Code)
	}
}

func TestWhitelistHandlerAcceptsRequests(t *testing.T) {
	ranges := []ipRange{
		newIPRange(net.ParseIP("201.2.2.4"), net.ParseIP("201.4.2.1")),
	}

	handler := &WhitelistHandler{allowedRanges: ranges, next: &MockHandler{}}

	resp := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "201.2.3.3:1001"

	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(resp, req)

	if resp.Code == http.StatusForbidden {
		t.Errorf("received 403, should not have")
	}

	if resp.Code != http.StatusOK {
		t.Errorf("expected 200 from next handler, got %s", resp.Code)
	}
}

func TestWhitelistHandlerAllowsLocalhost(t *testing.T) {
	ranges := []ipRange{
		newIPRange(net.ParseIP("102.1.1.1"), net.ParseIP("103.1.1.1")),
	}

	handler := &WhitelistHandler{allowedRanges: ranges, next: &MockHandler{}}

	resp := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1]:19191"

	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(resp, req)

	if resp.Code == http.StatusForbidden {
		t.Errorf("received 403, should not have")
	}

	if resp.Code != http.StatusOK {
		t.Errorf("expected 200 from next handler, got %s", resp.Code)
	}
}

type MockHandler struct {
}

func (m *MockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
}
