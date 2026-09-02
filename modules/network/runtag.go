package network

import "net/url"

// tagURL sets a mn=<runID> query parameter on rawURL so a consumer can
// correlate the request back to the run. Returns rawURL unchanged when runID
// is empty or the URL cannot be parsed.
func tagURL(rawURL, runID string) string {
	if runID == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("mn", runID)
	u.RawQuery = q.Encode()
	return u.String()
}
