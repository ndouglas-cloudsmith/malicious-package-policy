package example

import future.keywords.if
import future.keywords.in

# 1. Detailed Violation Messages
violation[msg] if {
    # Move the key inside the rule so it isn't globally exported to the JSON output
    osm_key := opa.runtime().env.OSM_KEY
    osm_key != ""

    some pkg in input.packages
    
    params := urlquery.encode_object({
        "report_type": "package",
        "resource_identifier": pkg.name,
        "ecosystem": pkg.ecosystem
    })
    
    url := sprintf("https://api.opensourcemalware.com/functions/v1/check-malicious?%s", [params])

    response := http.send({
        "method": "GET",
        "url": url,
        "headers": {"Authorization": sprintf("Bearer %s", [osm_key])}
    })

    response.body.malicious == true
    
    # This restores your descriptive string output
    msg := sprintf("BLOCKING INSTALL: '%s' is MALICIOUS. Description: %s", [pkg.name, response.body.details.description])
}

# 2. Simple list of safe packages
# We use a separate rule for 'safe' so it doesn't clutter the violation messages
safe_packages[pkg.name] if {
    some pkg in input.packages
    # A package is safe if its NAME does not appear in any violation message
    not some_violation_contains(pkg.name)
}

# Helper to link the name to the long description string
some_violation_contains(name) if {
    some msg in violation
    contains(msg, sprintf("'%s'", [name]))
}

allow if {
    count(violation) == 0
}
