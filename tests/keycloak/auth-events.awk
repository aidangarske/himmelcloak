# Himmelcloak native Keycloak authentication
# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
# Print only the Keycloak login event fields needed for the test trace.
# Session and token identifiers from the raw server log are omitted.
function value(line, key, parts, quoted) {
    split(line, parts, key "=\"")
    if (length(parts) < 2) {
        return ""
    }
    split(parts[2], quoted, "\"")
    return quoted[1]
}

/type="LOGIN(_ERROR)?"/ {
    printf "[keycloak server] %s client=%s user=%s grant=%s", \
        value($0, "type"), value($0, "clientId"), \
        value($0, "username"), value($0, "grant_type")
    error = value($0, "error")
    if (error != "") {
        printf " error=%s", error
    }
    print ""
    seen = 1
}

END {
    if (!seen) {
        print "(no LOGIN events appeared in Keycloak logs)"
    }
}
