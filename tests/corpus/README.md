# False-positive corpus

Hand-written responses modelled on well-configured production sites (strict nonce-based CSP,
SRI-protected CDN assets, properly prefixed cookies, SPA catch-all routing, specific-origin
CORS). They are **not** recorded traffic. The test asserts the scanner reports nothing
for each of them, so any new rule that fires here is a false-positive regression.

Format: `{"name", "description", "https": bool, "routes": {path: {"status", "headers", "body"}},
"groups": [...], "expect": [rule ids still expected]}`.
