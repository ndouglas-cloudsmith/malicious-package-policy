package example

import future.keywords.if
import future.keywords.in

osm_key := opa.runtime().env.OSM_KEY

# 1. The "Naughty List" (Violations)
# This identifies specific packages that are malicious
violation[pkg_name] if {
    some pkg in input.packages
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
    pkg_name := pkg.name
}

# 2. The "Nice List" (Safe)
# This returns any package name that is NOT in the violation set
safe_packages[pkg.name] if {
    some pkg in input.packages
    not violation[pkg.name]
}

# 3. Final Decision Logic
allow if {
    count(violation) == 0
}
