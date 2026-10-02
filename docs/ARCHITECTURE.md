# Architecture

A passive scanner: it reads what a server volunteers, maps findings to rules (CWE / OWASP), and emits console, JSON, markdown or SARIF output. It ships as a CLI and a GitHub Action.

```mermaid
flowchart LR
    User([CLI / GitHub Action]) --> CLI["cli.py<br/>args · config · exit codes 0/1/2"]
    Cfg[".websec.toml<br/>accepted risks + reasons"] --> CLI
    CLI --> Scan["scanner.py<br/>Scope · RateLimiter · crawler<br/>robots.txt · manual redirects"]
    Scan <-->|HTTP GET, TLS handshake| Target[(Target site)]
    Scan --> Html[htmlinfo.py<br/>parse page]

    subgraph Checks["checks/"]
        H[headers]
        C[cookies]
        T[tls]
        O[cors]
        P[content]
        E[exposure]
    end
    Scan --> Checks
    Html --> Checks
    Rules["rules.py<br/>rule catalog: severity · CWE · OWASP · fix"] --> Checks
    Checks --> Find[models.Finding]

    Find --> Base[baseline.py<br/>suppress accepted risks]
    Base --> Rep["report.py<br/>console · markdown · JSON"]
    Base --> Sarif["sarif.py<br/>SARIF 2.1.0"]
    Rules -.metadata.-> Rep
    Rules -.metadata.-> Sarif
    Sarif -->|upload-sarif| GH[(GitHub Security tab)]
    Rep -->|fail-on threshold| CLI
```
