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
