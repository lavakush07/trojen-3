package sbom

import future.keywords.if
import future.keywords.in

#### DEFINE YOUR DENY RULES BELOW ####
deny_list := fill_default_deny_rules([
{"name": {"value": "02-echo", "operator": "=="}, "version": {"value": "0.0.7", "operator": "=="}},
{"name": {"value": "@accordproject/concerto-analysis", "operator": "=="}, "version": {"value": "3.24.1", "operator": "=="}},
{"name": {"value": "@accordproject/concerto-linter", "operator": "=="}, "version": {"value": "3.24.1", "operator": "=="}},
{"name": {"value": "@accordproject/concerto-linter-default-ruleset", "operator": "=="}, "version": {"value": "3.24.1", "operator": "=="}},
{"name": {"value": "@accordproject/concerto-metamodel", "operator": "=="}, "version": {"value": "3.12.5", "operator": "=="}},
{"name": {"value": "@accordproject/concerto-types", "operator": "=="}, "version": {"value": "3.24.1", "operator": "=="}},
{"name": {"value": "@accordproject/markdown-it-cicero", "operator": "=="}, "version": {"value": "0.16.26", "operator": "=="}},
{"name": {"value": "@accordproject/template-engine", "operator": "=="}, "version": {"value": "2.7.2", "operator": "=="}},
{"name": {"value": "@actbase/css-to-react-native-transform", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "@actbase/native", "operator": "=="}, "version": {"value": "0.1.32", "operator": "=="}},
{"name": {"value": "@actbase/node-server", "operator": "=="}, "version": {"value": "1.1.19", "operator": "=="}},
{"name": {"value": "@actbase/react-absolute", "operator": "=="}, "version": {"value": "0.8.3", "operator": "=="}},
{"name": {"value": "@actbase/react-daum-postcode", "operator": "=="}, "version": {"value": "1.0.5", "operator": "=="}},
{"name": {"value": "@actbase/react-kakaosdk", "operator": "=="}, "version": {"value": "0.9.27", "operator": "=="}},
{"name": {"value": "@actbase/react-native-actionsheet", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "@actbase/react-native-devtools", "operator": "=="}, "version": {"value": "0.1.3", "operator": "=="}},
{"name": {"value": "@actbase/react-native-fast-image", "operator": "=="}, "version": {"value": "8.5.13", "operator": "=="}},
{"name": {"value": "@actbase/react-native-kakao-channel", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "@actbase/react-native-kakao-navi", "operator": "=="}, "version": {"value": "2.0.4", "operator": "=="}},
{"name": {"value": "@actbase/react-native-less-transformer", "operator": "=="}, "version": {"value": "1.0.6", "operator": "=="}},
{"name": {"value": "@actbase/react-native-naver-login", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "@actbase/react-native-simple-video", "operator": "=="}, "version": {"value": "1.0.13", "operator": "=="}},
{"name": {"value": "@actbase/react-native-tiktok", "operator": "=="}, "version": {"value": "1.1.3", "operator": "=="}},
{"name": {"value": "@afetcan/api", "operator": "=="}, "version": {"value": "0.0.13", "operator": "=="}},
{"name": {"value": "@afetcan/storage", "operator": "=="}, "version": {"value": "0.0.27", "operator": "=="}},
{"name": {"value": "@alaan/s2s-auth", "operator": "=="}, "version": {"value": "2.0.3", "operator": "=="}},
{"name": {"value": "@alexadark/amadeus-api", "operator": "=="}, "version": {"value": "1.0.4", "operator": "=="}},
{"name": {"value": "@alexadark/gatsby-theme-events", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "@alexadark/gatsby-theme-wordpress-blog", "operator": "=="}, "version": {"value": "2.0.1", "operator": "=="}},
{"name": {"value": "@alexadark/reusable-functions", "operator": "=="}, "version": {"value": "1.5.1", "operator": "=="}},
{"name": {"value": "@alexcolls/nuxt-socket.io", "operator": "=="}, "version": {"value": "0.0.7", "operator": "=="}},
{"name": {"value": "@alexcolls/nuxt-socket.io", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@alexcolls/nuxt-ux", "operator": "=="}, "version": {"value": "0.6.1", "operator": "=="}},
{"name": {"value": "@alexcolls/nuxt-ux", "operator": "=="}, "version": {"value": "0.6.2", "operator": "=="}},
{"name": {"value": "@antstackio/eslint-config-antstack", "operator": "=="}, "version": {"value": "0.0.3", "operator": "=="}},
{"name": {"value": "@antstackio/express-graphql-proxy", "operator": "=="}, "version": {"value": "0.2.8", "operator": "=="}},
{"name": {"value": "@antstackio/graphql-body-parser", "operator": "=="}, "version": {"value": "0.1.1", "operator": "=="}},
{"name": {"value": "@antstackio/json-to-graphql", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "@antstackio/shelbysam", "operator": "=="}, "version": {"value": "1.1.7", "operator": "=="}},
{"name": {"value": "@aryanhussain/my-angular-lib", "operator": "=="}, "version": {"value": "0.0.23", "operator": "=="}},
{"name": {"value": "@asyncapi/avro-schema-parser", "operator": "=="}, "version": {"value": "3.0.25", "operator": "=="}},
{"name": {"value": "@asyncapi/avro-schema-parser", "operator": "=="}, "version": {"value": "3.0.26", "operator": "=="}},
{"name": {"value": "@asyncapi/bundler", "operator": "=="}, "version": {"value": "0.6.5", "operator": "=="}},
{"name": {"value": "@asyncapi/bundler", "operator": "=="}, "version": {"value": "0.6.6", "operator": "=="}},
{"name": {"value": "@asyncapi/cli", "operator": "=="}, "version": {"value": "4.1.2", "operator": "=="}},
{"name": {"value": "@asyncapi/cli", "operator": "=="}, "version": {"value": "4.1.3", "operator": "=="}},
{"name": {"value": "@asyncapi/converter", "operator": "=="}, "version": {"value": "1.6.3", "operator": "=="}},
{"name": {"value": "@asyncapi/converter", "operator": "=="}, "version": {"value": "1.6.4", "operator": "=="}},
{"name": {"value": "@asyncapi/diff", "operator": "=="}, "version": {"value": "0.5.1", "operator": "=="}},
{"name": {"value": "@asyncapi/diff", "operator": "=="}, "version": {"value": "0.5.2", "operator": "=="}},
{"name": {"value": "@asyncapi/dotnet-rabbitmq-template", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "@asyncapi/dotnet-rabbitmq-template", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "@asyncapi/edavisualiser", "operator": "=="}, "version": {"value": "1.2.1", "operator": "=="}},
{"name": {"value": "@asyncapi/edavisualiser", "operator": "=="}, "version": {"value": "1.2.2", "operator": "=="}},
{"name": {"value": "@asyncapi/generator", "operator": "=="}, "version": {"value": "2.8.5", "operator": "=="}},
{"name": {"value": "@asyncapi/generator", "operator": "=="}, "version": {"value": "2.8.6", "operator": "=="}},
{"name": {"value": "@asyncapi/generator-components", "operator": "=="}, "version": {"value": "0.3.2", "operator": "=="}},
{"name": {"value": "@asyncapi/generator-components", "operator": "=="}, "version": {"value": "0.3.3", "operator": "=="}},
{"name": {"value": "@asyncapi/generator-helpers", "operator": "=="}, "version": {"value": "0.2.1", "operator": "=="}},
{"name": {"value": "@asyncapi/generator-helpers", "operator": "=="}, "version": {"value": "0.2.2", "operator": "=="}},
{"name": {"value": "@asyncapi/generator-react-sdk", "operator": "=="}, "version": {"value": "1.1.4", "operator": "=="}},
{"name": {"value": "@asyncapi/generator-react-sdk", "operator": "=="}, "version": {"value": "1.1.5", "operator": "=="}},
{"name": {"value": "@asyncapi/go-watermill-template", "operator": "=="}, "version": {"value": "0.2.76", "operator": "=="}},
{"name": {"value": "@asyncapi/go-watermill-template", "operator": "=="}, "version": {"value": "0.2.77", "operator": "=="}},
{"name": {"value": "@asyncapi/html-template", "operator": "=="}, "version": {"value": "3.3.2", "operator": "=="}},
{"name": {"value": "@asyncapi/html-template", "operator": "=="}, "version": {"value": "3.3.3", "operator": "=="}},
{"name": {"value": "@asyncapi/java-spring-cloud-stream-template", "operator": "=="}, "version": {"value": "0.13.5", "operator": "=="}},
{"name": {"value": "@asyncapi/java-spring-cloud-stream-template", "operator": "=="}, "version": {"value": "0.13.6", "operator": "=="}},
{"name": {"value": "@asyncapi/java-spring-template", "operator": "=="}, "version": {"value": "1.6.1", "operator": "=="}},
{"name": {"value": "@asyncapi/java-spring-template", "operator": "=="}, "version": {"value": "1.6.2", "operator": "=="}},
{"name": {"value": "@asyncapi/java-template", "operator": "=="}, "version": {"value": "0.3.5", "operator": "=="}},
{"name": {"value": "@asyncapi/java-template", "operator": "=="}, "version": {"value": "0.3.6", "operator": "=="}},
{"name": {"value": "@asyncapi/keeper", "operator": "=="}, "version": {"value": "0.0.2", "operator": "=="}},
{"name": {"value": "@asyncapi/keeper", "operator": "=="}, "version": {"value": "0.0.3", "operator": "=="}},
{"name": {"value": "@asyncapi/markdown-template", "operator": "=="}, "version": {"value": "1.6.8", "operator": "=="}},
{"name": {"value": "@asyncapi/markdown-template", "operator": "=="}, "version": {"value": "1.6.9", "operator": "=="}},
{"name": {"value": "@asyncapi/modelina", "operator": "=="}, "version": {"value": "5.10.3", "operator": "=="}},
{"name": {"value": "@asyncapi/modelina-cli", "operator": "=="}, "version": {"value": "5.10.2", "operator": "=="}},
{"name": {"value": "@asyncapi/modelina-cli", "operator": "=="}, "version": {"value": "5.10.3", "operator": "=="}},
{"name": {"value": "@asyncapi/multi-parser", "operator": "=="}, "version": {"value": "2.2.1", "operator": "=="}},
{"name": {"value": "@asyncapi/multi-parser", "operator": "=="}, "version": {"value": "2.2.2", "operator": "=="}},
{"name": {"value": "@asyncapi/nodejs-template", "operator": "=="}, "version": {"value": "3.0.5", "operator": "=="}},
{"name": {"value": "@asyncapi/nodejs-template", "operator": "=="}, "version": {"value": "3.0.6", "operator": "=="}},
{"name": {"value": "@asyncapi/nodejs-ws-template", "operator": "=="}, "version": {"value": "0.10.1", "operator": "=="}},
{"name": {"value": "@asyncapi/nodejs-ws-template", "operator": "=="}, "version": {"value": "0.10.2", "operator": "=="}},
{"name": {"value": "@asyncapi/nunjucks-filters", "operator": "=="}, "version": {"value": "2.1.1", "operator": "=="}},
{"name": {"value": "@asyncapi/nunjucks-filters", "operator": "=="}, "version": {"value": "2.1.2", "operator": "=="}},
{"name": {"value": "@asyncapi/openapi-schema-parser", "operator": "=="}, "version": {"value": "3.0.25", "operator": "=="}},
{"name": {"value": "@asyncapi/openapi-schema-parser", "operator": "=="}, "version": {"value": "3.0.26", "operator": "=="}},
{"name": {"value": "@asyncapi/optimizer", "operator": "=="}, "version": {"value": "1.0.5", "operator": "=="}},
{"name": {"value": "@asyncapi/optimizer", "operator": "=="}, "version": {"value": "1.0.6", "operator": "=="}},
{"name": {"value": "@asyncapi/parser", "operator": "=="}, "version": {"value": "3.4.1", "operator": "=="}},
{"name": {"value": "@asyncapi/parser", "operator": "=="}, "version": {"value": "3.4.2", "operator": "=="}},
{"name": {"value": "@asyncapi/php-template", "operator": "=="}, "version": {"value": "0.1.1", "operator": "=="}},
{"name": {"value": "@asyncapi/php-template", "operator": "=="}, "version": {"value": "0.1.2", "operator": "=="}},
{"name": {"value": "@asyncapi/problem", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "@asyncapi/problem", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "@asyncapi/protobuf-schema-parser", "operator": "=="}, "version": {"value": "3.5.2", "operator": "=="}},
{"name": {"value": "@asyncapi/protobuf-schema-parser", "operator": "=="}, "version": {"value": "3.5.3", "operator": "=="}},
{"name": {"value": "@asyncapi/protobuf-schema-parser", "operator": "=="}, "version": {"value": "3.6.1", "operator": "=="}},
{"name": {"value": "@asyncapi/python-paho-template", "operator": "=="}, "version": {"value": "0.2.14", "operator": "=="}},
{"name": {"value": "@asyncapi/python-paho-template", "operator": "=="}, "version": {"value": "0.2.15", "operator": "=="}},
{"name": {"value": "@asyncapi/react-component", "operator": "=="}, "version": {"value": "2.6.6", "operator": "=="}},
{"name": {"value": "@asyncapi/react-component", "operator": "=="}, "version": {"value": "2.6.7", "operator": "=="}},
{"name": {"value": "@asyncapi/server-api", "operator": "=="}, "version": {"value": "0.16.24", "operator": "=="}},
{"name": {"value": "@asyncapi/server-api", "operator": "=="}, "version": {"value": "0.16.25", "operator": "=="}},
{"name": {"value": "@asyncapi/specs", "operator": "=="}, "version": {"value": "6.8.3", "operator": "=="}},
{"name": {"value": "@asyncapi/specs", "operator": "=="}, "version": {"value": "6.9.1", "operator": "=="}},
{"name": {"value": "@asyncapi/studio", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "@asyncapi/studio", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "@asyncapi/web-component", "operator": "=="}, "version": {"value": "2.6.6", "operator": "=="}},
{"name": {"value": "@asyncapi/web-component", "operator": "=="}, "version": {"value": "2.6.7", "operator": "=="}},
{"name": {"value": "@bdkinc/knex-ibmi", "operator": "=="}, "version": {"value": "0.5.7", "operator": "=="}},
{"name": {"value": "@browserbasehq/bb9", "operator": "=="}, "version": {"value": "1.2.21", "operator": "=="}},
{"name": {"value": "@browserbasehq/director-ai", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "@browserbasehq/mcp", "operator": "=="}, "version": {"value": "2.1.1", "operator": "=="}},
{"name": {"value": "@browserbasehq/mcp-server-browserbase", "operator": "=="}, "version": {"value": "2.4.2", "operator": "=="}},
{"name": {"value": "@browserbasehq/sdk-functions", "operator": "=="}, "version": {"value": "0.0.4", "operator": "=="}},
{"name": {"value": "@browserbasehq/stagehand", "operator": "=="}, "version": {"value": "3.0.4", "operator": "=="}},
{"name": {"value": "@browserbasehq/stagehand-docs", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "@caretive/caret-cli", "operator": "=="}, "version": {"value": "0.0.2", "operator": "=="}},
{"name": {"value": "@chtijs/eslint-config", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "@clausehq/flows-step-httprequest", "operator": "=="}, "version": {"value": "0.1.14", "operator": "=="}},
{"name": {"value": "@clausehq/flows-step-jsontoxml", "operator": "=="}, "version": {"value": "0.1.14", "operator": "=="}},
{"name": {"value": "@clausehq/flows-step-mqtt", "operator": "=="}, "version": {"value": "0.1.14", "operator": "=="}},
{"name": {"value": "@clausehq/flows-step-sendgridemail", "operator": "=="}, "version": {"value": "0.1.14", "operator": "=="}},
{"name": {"value": "@clausehq/flows-step-taskscreateurl", "operator": "=="}, "version": {"value": "0.1.14", "operator": "=="}},
{"name": {"value": "@cllbk/ghl", "operator": "=="}, "version": {"value": "1.3.1", "operator": "=="}},
{"name": {"value": "@commute/bloom", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "@commute/market-data", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "@commute/market-data-chartjs", "operator": "=="}, "version": {"value": "2.3.1", "operator": "=="}},
{"name": {"value": "@dev-blinq/ai-qa-logic", "operator": "=="}, "version": {"value": "1.0.19", "operator": "=="}},
{"name": {"value": "@dev-blinq/blinqioclient", "operator": "=="}, "version": {"value": "1.0.21", "operator": "=="}},
{"name": {"value": "@dev-blinq/cucumber-js", "operator": "=="}, "version": {"value": "1.0.131", "operator": "=="}},
{"name": {"value": "@dev-blinq/cucumber_client", "operator": "=="}, "version": {"value": "1.0.738", "operator": "=="}},
{"name": {"value": "@dev-blinq/ui-systems", "operator": "=="}, "version": {"value": "1.0.93", "operator": "=="}},
{"name": {"value": "@ensdomains/address-encoder", "operator": "=="}, "version": {"value": "1.1.5", "operator": "=="}},
{"name": {"value": "@ensdomains/blacklist", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "@ensdomains/buffer", "operator": "=="}, "version": {"value": "0.1.2", "operator": "=="}},
{"name": {"value": "@ensdomains/ccip-read-cf-worker", "operator": "=="}, "version": {"value": "0.0.4", "operator": "=="}},
{"name": {"value": "@ensdomains/ccip-read-dns-gateway", "operator": "=="}, "version": {"value": "0.1.1", "operator": "=="}},
{"name": {"value": "@ensdomains/ccip-read-router", "operator": "=="}, "version": {"value": "0.0.7", "operator": "=="}},
{"name": {"value": "@ensdomains/ccip-read-worker-viem", "operator": "=="}, "version": {"value": "0.0.4", "operator": "=="}},
{"name": {"value": "@ensdomains/content-hash", "operator": "=="}, "version": {"value": "3.0.1", "operator": "=="}},
{"name": {"value": "@ensdomains/curvearithmetics", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "@ensdomains/cypress-metamask", "operator": "=="}, "version": {"value": "1.2.1", "operator": "=="}},
{"name": {"value": "@ensdomains/dnsprovejs", "operator": "=="}, "version": {"value": "0.5.3", "operator": "=="}},
{"name": {"value": "@ensdomains/dnssec-oracle-anchors", "operator": "=="}, "version": {"value": "0.0.2", "operator": "=="}},
{"name": {"value": "@ensdomains/dnssecoraclejs", "operator": "=="}, "version": {"value": "0.2.9", "operator": "=="}},
{"name": {"value": "@ensdomains/durin", "operator": "=="}, "version": {"value": "0.1.2", "operator": "=="}},

])

#### DEFINE YOUR ALLOW RULES BELOW ####
allow_list := {
	"licenses": [],
	"purls": [],
	"suppliers": [],
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

