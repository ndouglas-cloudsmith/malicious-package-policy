package example

import future.keywords.if
import future.keywords.in

# 1. Define the Violation Rule
violation[msg] if {
    some pkg in input.packages
    
    # Perform the API call to OSV.dev
    response := http.send({
        "method": "POST",
        "url": "https://api.osv.dev/v1/query",
        "body": {
            "version": pkg.version,
            "package": {
                "name": pkg.name, 
                "ecosystem": pkg.ecosystem
            }
        }
    })

    # Check if the 'vulns' key exists in the response body
    # OSV returns an empty object {} if no vulnerabilities are found.
    count(response.body.vulns) > 0
    
    # Check if any of those vulnerabilities are specifically tagged as 'MALICIOUS'
    some vuln in response.body.vulns
    is_malicious(vuln)
    
    msg := sprintf("BLOCKING INSTALL: Package '%s' (v%s) is flagged as MALICIOUS by OSV.dev", [pkg.name, pkg.version])
}

# Helper function to check for the MALICIOUS tag or summary
is_malicious(vuln) if {
    "MALICIOUS" in vuln.tags
}

is_malicious(vuln) if {
    contains(lower(vuln.summary), "malicious")
}

# 2. Main Allow Logic
allow if {
    count(violation) == 0
}
