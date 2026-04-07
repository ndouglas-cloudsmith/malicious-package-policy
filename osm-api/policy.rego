package example

import future.keywords.if
import future.keywords.in

# 1. Internal rule to identify malicious packages (Hides Key)
# This won't show up in your output unless you specifically query it.
is_malicious_package[pkg.name] if {
    some pkg in input.packages
    
    # Key is local here, so it won't leak to the global document
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

# 2. The Detailed Violation Output (The one you liked)
violation[msg] if {
    some name in is_malicious_package
    
    # We re-fetch the description here (OPA caches the http.send call 
    # from above, so this doesn't actually hit the network again)
    some pkg in input.packages
    pkg.name == name
    
    osm_key := opa.runtime().env.OSM_KEY
    params := urlquery.encode_object({"report_type": "package", "resource_identifier": name, "ecosystem": pkg.ecosystem})
    url := sprintf("https://api.opensourcemalware.com/functions/v1/check-malicious?%s", [params])
    
    response := http.send({
        "method": "GET",
        "url": url,
        "headers": {"Authorization": sprintf("Bearer %s", [osm_key])}
    })

    msg := sprintf("BLOCKING INSTALL: '%s' is MALICIOUS. Description: %s", [name, response.body.details.description])
}

# 3. Simple list of safe packages
safe_packages[pkg.name] if {
    some pkg in input.packages
    not is_malicious_package[pkg.name]
}

allow if {
    count(is_malicious_package) == 0
}
