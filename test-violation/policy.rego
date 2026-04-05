package example

# 1. Define a set of violation messages
violation[msg] if {
    some pkg in input.packages
    pkg.name == "malicious-pkg"
    msg := sprintf("SECURITY ALERT: Package '%s' (v%s) is blacklisted.", [pkg.name, pkg.version])
}

# 2. You can add more rules to the same violation set
violation[msg] if {
    some pkg in input.packages
    not pkg.version  # Check if version is missing
    msg := sprintf("COMPLIANCE ERROR: Package '%s' must have a pinned version.", [pkg.name])
}

# 3. Allow only if there are no violations
allow if {
    count(violation) == 0
}
