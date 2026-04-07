package example

import future.keywords.if
import future.keywords.in

# 1. Gather all info about malicious packages in one structured object
# This maps the package name to its full API response details
_malicious_details[pkg.name] := response.body if {
    some pkg in input.packages
    
    osm_key := opa.runtime().env.OSM_KEY
    osm_key != ""

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
}

# 2. Violation Messages (The format you wanted)
violation[msg] if {
    # Iterate over the keys (names) and values (details) of our helper object
    some name, details in _malicious_details
    msg := sprintf("BLOCKING INSTALL: '%s' is MALICIOUS. Description: %s", [name, details.details.description])
}

# 3. Safe Packages
safe_packages[pkg.name] if {
    some pkg in input.packages
    # If the name isn't a key in our malicious details object, it's safe
    not _malicious_details[pkg.name]
}

# 4. Decision Logic
allow if {
    count(_malicious_details) == 0
}
