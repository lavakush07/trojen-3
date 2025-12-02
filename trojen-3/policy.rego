package sbom

import future.keywords.if
import future.keywords.in

#### DEFINE YOUR DENY RULES BELOW ####
deny_list := fill_default_deny_rules([
	{
		"name": {"value": "zlib", "operator": "=="},
		"version": {"value": "1.2.13", "operator": "<="},
	},
  {"license": {"value": "BSD-2-Clause", "operator": "=="}},
])

#### DEFINE YOUR ALLOW RULES BELOW ####
allow_list := {
	"licenses": [
		{"license": {
			"value": "MIT",
			"operator": "==",
		}},
		{"license": {
			"value": "NOASSERTION",
			"operator": "==",
		}},
		{"license": {
			"value": "NO_ASSERTION",
			"operator": "==",
		}},
    {"license": {
			"value": "GPL-2.0-only",
			"operator": "==",
		}},
    {"license": {
			"value": "MPL-2.0",
			"operator": "==",
		}},
    {"license": {
			"value": "Zlib",
			"operator": "==",
		}},
    {"license": {
			"value": "Apache-2.0",
			"operator": "==",
		}},
    {"license": {
			"value": "BSD-3-Clause",
			"operator": "==",
		}},
	],
}

#### DO NOT CHANGE THE FOLLOWING SCRIPT ####

does_violate_license(pkg, rules) if {
	some package_license in pkg.packageLicense
	not does_match_license(package_license, rules)
}

does_match_license(license, rules) if {
	some rule in rules
	str_compare(license, rule.license.operator, rule.license.value)
}

does_violate_purl(pkg, rules) if {
	not does_match_purl(pkg, rules)
}

does_match_purl(pkg, rules) if {
	some rule in rules
	str_compare(pkg.purl, rule.purl.operator, rule.purl.value)
}

does_violate_purl(pkg, _) if {
	not pkg.purl
}

does_violate_supplier(pkg, rules) if {
	not does_match_supplier(pkg, rules)
}

does_violate_supplier(pkg, _) if {
	not pkg.packageOriginatorName
}

does_match_supplier(pkg, rules) if {
	some rule in rules
	str_compare(pkg.packageOriginatorName, rule.supplier.operator, rule.supplier.value)
}

allow_rules_licenses_violations(allow_rules_licenses) := violating_packages if {
	violating_packages := {result |
		some pkg in input
		does_violate_license(pkg, allow_rules_licenses)
		result = pkg.uuid
	}
	count(violating_packages) > 0
}

allow_rules_purls_violations(allow_rules_purls) := violating_packages if {
	violating_packages := {result |
		some pkg in input
		does_violate_purl(pkg, allow_rules_purls)
		result = pkg.uuid
	}
	count(violating_packages) > 0
}

allow_rules_suppliers_violations(allow_rules_suppliers) := violating_packages if {
	violating_packages := {result |
		some pkg in input
		does_violate_supplier(pkg, allow_rules_suppliers)
		result = pkg.uuid
	}
	count(violating_packages) > 0
}

allow_list_violations[violations] {
	allow_rules_licenses := object.get(allow_list, "licenses", [])
	count(allow_rules_licenses) > 0
	violations := [x |
		x := {
			"type": "allow",
			"rule": allow_rules_licenses,
			"violations": allow_rules_licenses_violations(allow_rules_licenses),
		}
	]
	count(violations) > 0
}

allow_list_violations[violations] {
	allow_rules_purls := object.get(allow_list, "purls", [])
	count(allow_rules_purls) > 0
	violations := [x |
		x := {
			"type": "allow",
			"rule": allow_rules_purls,
			"violations": allow_rules_purls_violations(allow_rules_purls),
		}
	]
	count(violations) > 0
}

allow_list_violations[violations] {
	allow_rules_suppliers := object.get(allow_list, "suppliers", [])
	count(allow_rules_suppliers) > 0
	violations := [x |
		x := {
			"type": "allow",
			"rule": allow_rules_suppliers,
			"violations": allow_rules_suppliers_violations(allow_rules_suppliers),
		}
	]
	count(violations) > 0
}

deny_list_violations[violations] {
	some deny_rule in deny_list
	violations := [x |
		x := {
			"type": "deny",
			"rule": deny_rule,
			"violations": [violating_id |
				some pkg in input
				violating_id := pkg.uuid
				deny_compare(pkg, deny_rule)
			],
		}
	]
	count(violations) > 0
}

deny_compare(pkg, rule) if {
	license_match := [x |
		x := true
		some license, package_license in pkg.packageLicense
		str_compare(package_license, rule.license.operator, rule.license.value)
	]
	count(license_match) != 0

	is_name_denied(pkg, rule)
	is_purl_denied(pkg, rule)
	is_supplier_denied(pkg, rule)
	pkg_version := version_to_semver(pkg.packageVersion)
	rule_version := version_to_semver(rule.version.value)
	semver_compare(pkg_version, rule.version.operator, rule_version)
}

version_to_semver(version) = output if {
	parts := split(version, ".")
	count(parts) == 1
	output := concat(".", [version, "0", "0"])
}

version_to_semver(version) = output if {
	parts := split(version, ".")
	count(parts) == 2
	output := concat(".", [version, "0"])
}

version_to_semver(version) = version if {
	parts := split(version, ".")
	count(parts) >= 3
}

is_supplier_denied(pkg, rule) if {
	not pkg.packageOriginatorName
	rule.supplier.value == null
}

is_name_denied(pkg, rule) if {
	not pkg.packageName
	rule.name.value == null
}

is_purl_denied(pkg, rule) if {
	not pkg.purl
	rule.purl.value == null
}

is_supplier_denied(pkg, rule) if {
	str_compare(pkg.packageOriginatorName, rule.supplier.operator, rule.supplier.value)
}

is_name_denied(pkg, rule) if {
	str_compare(pkg.packageName, rule.name.operator, rule.name.value)
}

is_purl_denied(pkg, rule) if {
	str_compare(pkg.purl, rule.purl.operator, rule.purl.value)
}

str_compare(a, "==", b) := a == b

str_compare(a, "!", b) := a != b

str_compare(a, "~", b) := regex.match(b, a)

str_compare(a, null, b) := a == b if b != null

str_compare(_, null, null) := true

semver_compare(a, "<=", b) := semver.compare(a, b) <= 0

semver_compare(a, "<", b) := semver.compare(a, b) < 0

semver_compare(a, "==", b) := semver.compare(a, b) == 0

semver_compare(a, ">", b) := semver.compare(a, b) > 0

semver_compare(a, ">=", b) := semver.compare(a, b) >= 0

semver_compare(a, "!", b) := semver.compare(a, b) != 0

semver_compare(a, "><", b) if {
	ys := split(b, ",")
	firstValue := ys[0]
	secondValue := ys[1]
	semver.compare(a, firstValue) > 0
	semver.compare(a, secondValue) < 0
}

semver_compare(a, ">=<", b) if {
	ys := split(b, ",")
	firstValue := ys[0]
	secondValue := ys[1]
	semver.compare(a, firstValue) >= 0
	semver.compare(a, secondValue) < 0
}

semver_compare(a, ">=<=", b) if {
	ys := split(b, ",")
	firstValue := ys[0]
	secondValue := ys[1]
	semver.compare(a, firstValue) >= 0
	semver.compare(a, secondValue) <= 0
}

semver_compare(a, "><=", b) if {
	ys := split(b, ",")
	firstValue := ys[0]
	secondValue := ys[1]
	semver.compare(a, firstValue) > 0
	semver.compare(a, secondValue) <= 0
}

version_to_semver(version) = output if {
	version == null
	output := null
}

semver_compare(a, "~", b) := regex.match(b, a)

semver_compare(a, null, b) := semver.compare(b, a) == 0 if b != null

semver_compare(_, null, null) := true

fill_default_deny_rules(obj) := list if {
	defaults := {
		"name": {"value": null, "operator": null},
		"license": {"value": null, "operator": null},
		"version": {"value": null, "operator": null},
		"supplier": {"value": null, "operator": null},
		"purl": {"value": null, "operator": null},
	}
	list := [x | x := object.union(defaults, obj[_])]
}
