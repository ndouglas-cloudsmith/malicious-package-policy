package example

import future.keywords.if
import future.keywords.in

# 1. Access the environment variable
# This assumes you have exported OSM_KEY in your shell or container
osm_key := opa.runtime().env.OSM_KEY

violation[msg] if {
    some pkg in input.packages
    
    # Check if the key is actually present to avoid 401 errors
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
        "headers": {
            "Authorization": sprintf("Bearer %s", [osm_key])
        }
    })

    response.body.malicious == true
    
    msg := sprintf("BLOCKING INSTALL: '%s' is MALICIOUS. Description: %s", [pkg.name, response.body.details.description])
}

allow if {
    count(violation) == 0
}
