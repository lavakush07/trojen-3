package scs.package_protection

# Denylist of malicious or compromised NPM packages.
# All entries must be consolidated here.
denylist := {

[
{"name": {"value": "02-echo", "operator": "=="}, "version": {"value": "0.0.7", "operator": "=="}},
{"name": {"value": "@accordproject/concerto-analysis", "operator": "=="}, "version": {"value": "3.24.1", "operator": "=="}},
{"name": {"value": "@accordproject/concerto-linter", "operator": "=="}, "version": {"value": "3.24.1", "operator": "=="}},
{"name": {"value": "@accordproject/concerto-linter-default-ruleset", "operator": "=="}, "version": {"value": "3.24.1", "operator": "=="}},
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
{"name": {"value": "@ensdomains/durin-middleware", "operator": "=="}, "version": {"value": "0.0.2", "operator": "=="}},
{"name": {"value": "@ensdomains/ens-archived-contracts", "operator": "=="}, "version": {"value": "0.0.3", "operator": "=="}},
{"name": {"value": "@ensdomains/ens-avatar", "operator": "=="}, "version": {"value": "1.0.4", "operator": "=="}},
{"name": {"value": "@ensdomains/ens-contracts", "operator": "=="}, "version": {"value": "1.6.1", "operator": "=="}},
{"name": {"value": "@ensdomains/ens-test-env", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "@ensdomains/ens-validation", "operator": "=="}, "version": {"value": "0.1.1", "operator": "=="}},
{"name": {"value": "@ensdomains/ensjs", "operator": "=="}, "version": {"value": "4.0.3", "operator": "=="}},
{"name": {"value": "@ensdomains/ensjs-react", "operator": "=="}, "version": {"value": "0.0.5", "operator": "=="}},
{"name": {"value": "@ensdomains/eth-ens-namehash", "operator": "=="}, "version": {"value": "2.0.16", "operator": "=="}},
{"name": {"value": "@ensdomains/hackathon-registrar", "operator": "=="}, "version": {"value": "1.0.5", "operator": "=="}},
{"name": {"value": "@ensdomains/hardhat-chai-matchers-viem", "operator": "=="}, "version": {"value": "0.1.15", "operator": "=="}},
{"name": {"value": "@ensdomains/hardhat-toolbox-viem-extended", "operator": "=="}, "version": {"value": "0.0.6", "operator": "=="}},
{"name": {"value": "@ensdomains/mock", "operator": "=="}, "version": {"value": "2.1.52", "operator": "=="}},
{"name": {"value": "@ensdomains/name-wrapper", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "@ensdomains/offchain-resolver-contracts", "operator": "=="}, "version": {"value": "0.2.2", "operator": "=="}},
{"name": {"value": "@ensdomains/op-resolver-contracts", "operator": "=="}, "version": {"value": "0.0.2", "operator": "=="}},
{"name": {"value": "@ensdomains/react-ens-address", "operator": "=="}, "version": {"value": "0.0.32", "operator": "=="}},
{"name": {"value": "@ensdomains/renewal", "operator": "=="}, "version": {"value": "0.0.13", "operator": "=="}},
{"name": {"value": "@ensdomains/renewal-widget", "operator": "=="}, "version": {"value": "0.1.10", "operator": "=="}},
{"name": {"value": "@ensdomains/reverse-records", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "@ensdomains/server-analytics", "operator": "=="}, "version": {"value": "0.0.2", "operator": "=="}},
{"name": {"value": "@ensdomains/solsha1", "operator": "=="}, "version": {"value": "0.0.4", "operator": "=="}},
{"name": {"value": "@ensdomains/subdomain-registrar", "operator": "=="}, "version": {"value": "0.2.4", "operator": "=="}},
{"name": {"value": "@ensdomains/test-utils", "operator": "=="}, "version": {"value": "1.3.1", "operator": "=="}},
{"name": {"value": "@ensdomains/thorin", "operator": "=="}, "version": {"value": "0.6.51", "operator": "=="}},
{"name": {"value": "@ensdomains/ui", "operator": "=="}, "version": {"value": "3.4.6", "operator": "=="}},
{"name": {"value": "@ensdomains/unicode-confusables", "operator": "=="}, "version": {"value": "0.1.1", "operator": "=="}},
{"name": {"value": "@ensdomains/unruggable-gateways", "operator": "=="}, "version": {"value": "0.0.3", "operator": "=="}},
{"name": {"value": "@ensdomains/vite-plugin-i18next-loader", "operator": "=="}, "version": {"value": "4.0.4", "operator": "=="}},
{"name": {"value": "@ensdomains/web3modal", "operator": "=="}, "version": {"value": "1.10.2", "operator": "=="}},
{"name": {"value": "@everreal/react-charts", "operator": "=="}, "version": {"value": "2.0.2", "operator": "=="}},
{"name": {"value": "@everreal/validate-esmoduleinterop-imports", "operator": "=="}, "version": {"value": "1.4.5", "operator": "=="}},
{"name": {"value": "@everreal/web-analytics", "operator": "=="}, "version": {"value": "0.0.2", "operator": "=="}},
{"name": {"value": "@faq-component/core", "operator": "=="}, "version": {"value": "0.0.4", "operator": "=="}},
{"name": {"value": "@faq-component/react", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "@fishingbooker/browser-sync-plugin", "operator": "=="}, "version": {"value": "1.0.5", "operator": "=="}},
{"name": {"value": "@fishingbooker/react-loader", "operator": "=="}, "version": {"value": "1.0.7", "operator": "=="}},
{"name": {"value": "@fishingbooker/react-pagination", "operator": "=="}, "version": {"value": "2.0.6", "operator": "=="}},
{"name": {"value": "@fishingbooker/react-raty", "operator": "=="}, "version": {"value": "2.0.1", "operator": "=="}},
{"name": {"value": "@fishingbooker/react-swiper", "operator": "=="}, "version": {"value": "0.1.5", "operator": "=="}},
{"name": {"value": "@hapheus/n8n-nodes-pgp", "operator": "=="}, "version": {"value": "1.5.1", "operator": "=="}},
{"name": {"value": "@hover-design/core", "operator": "=="}, "version": {"value": "0.0.1", "operator": "=="}},
{"name": {"value": "@hover-design/react", "operator": "=="}, "version": {"value": "0.2.1", "operator": "=="}},
{"name": {"value": "@huntersofbook/auth-vue", "operator": "=="}, "version": {"value": "0.4.2", "operator": "=="}},
{"name": {"value": "@huntersofbook/core", "operator": "=="}, "version": {"value": "0.5.1", "operator": "=="}},
{"name": {"value": "@huntersofbook/core-nuxt", "operator": "=="}, "version": {"value": "0.4.2", "operator": "=="}},
{"name": {"value": "@huntersofbook/form-naiveui", "operator": "=="}, "version": {"value": "0.5.1", "operator": "=="}},
{"name": {"value": "@huntersofbook/i18n", "operator": "=="}, "version": {"value": "0.8.2", "operator": "=="}},
{"name": {"value": "@huntersofbook/ui", "operator": "=="}, "version": {"value": "0.5.1", "operator": "=="}},
{"name": {"value": "@hyperlook/telemetry-sdk", "operator": "=="}, "version": {"value": "1.0.19", "operator": "=="}},
{"name": {"value": "@ifelsedeveloper/protocol-contracts-svm-idl", "operator": "=="}, "version": {"value": "0.1.2", "operator": "=="}},
{"name": {"value": "@ifelsedeveloper/protocol-contracts-svm-idl", "operator": "=="}, "version": {"value": "0.1.3", "operator": "=="}},
{"name": {"value": "@markvivanco/app-version-checker", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "@mcp-use/cli", "operator": "=="}, "version": {"value": "2.2.6", "operator": "=="}},
{"name": {"value": "@mcp-use/cli", "operator": "=="}, "version": {"value": "2.2.7", "operator": "=="}},
{"name": {"value": "@mcp-use/inspector", "operator": "=="}, "version": {"value": "0.6.2", "operator": "=="}},
{"name": {"value": "@mcp-use/inspector", "operator": "=="}, "version": {"value": "0.6.3", "operator": "=="}},
{"name": {"value": "@mcp-use/mcp-use", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "@mcp-use/mcp-use", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "@orbitgtbelgium/mapbox-gl-draw-cut-polygon-mode", "operator": "=="}, "version": {"value": "2.0.5", "operator": "=="}},
{"name": {"value": "@orbitgtbelgium/mapbox-gl-draw-scale-rotate-mode", "operator": "=="}, "version": {"value": "1.1.1", "operator": "=="}},
{"name": {"value": "@orbitgtbelgium/orbit-components", "operator": "=="}, "version": {"value": "1.2.9", "operator": "=="}},
{"name": {"value": "@orbitgtbelgium/time-slider", "operator": "=="}, "version": {"value": "1.0.187", "operator": "=="}},
{"name": {"value": "@osmanekrem/bmad", "operator": "=="}, "version": {"value": "1.0.6", "operator": "=="}},
{"name": {"value": "@osmanekrem/error-handler", "operator": "=="}, "version": {"value": "1.2.2", "operator": "=="}},
{"name": {"value": "@pergel/cli", "operator": "=="}, "version": {"value": "0.11.1", "operator": "=="}},
{"name": {"value": "@pergel/module-box", "operator": "=="}, "version": {"value": "0.6.1", "operator": "=="}},
{"name": {"value": "@pergel/module-graphql", "operator": "=="}, "version": {"value": "0.6.1", "operator": "=="}},
{"name": {"value": "@pergel/module-ui", "operator": "=="}, "version": {"value": "0.0.9", "operator": "=="}},
{"name": {"value": "@pergel/nuxt", "operator": "=="}, "version": {"value": "0.25.5", "operator": "=="}},
{"name": {"value": "@posthog/agent", "operator": "=="}, "version": {"value": "1.24.1", "operator": "=="}},
{"name": {"value": "@posthog/ai", "operator": "=="}, "version": {"value": "7.1.2", "operator": "=="}},
{"name": {"value": "@posthog/automatic-cohorts-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/bitbucket-release-tracker", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/cli", "operator": "=="}, "version": {"value": "0.5.15", "operator": "=="}},
{"name": {"value": "@posthog/clickhouse", "operator": "=="}, "version": {"value": "1.7.1", "operator": "=="}},
{"name": {"value": "@posthog/core", "operator": "=="}, "version": {"value": "1.5.6", "operator": "=="}},
{"name": {"value": "@posthog/currency-normalization-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/customerio-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/databricks-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/drop-events-on-property-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/event-sequence-timer-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/filter-out-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/first-time-event-tracker", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/geoip-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/github-release-tracking-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/gitub-star-sync-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/heartbeat-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/hedgehog-mode", "operator": "=="}, "version": {"value": "0.0.42", "operator": "=="}},
{"name": {"value": "@posthog/icons", "operator": "=="}, "version": {"value": "0.36.1", "operator": "=="}},
{"name": {"value": "@posthog/ingestion-alert-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/intercom-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/kinesis-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/laudspeaker-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/lemon-ui", "operator": "=="}, "version": {"value": "0.0.1", "operator": "=="}},
{"name": {"value": "@posthog/maxmind-plugin", "operator": "=="}, "version": {"value": "0.1.6", "operator": "=="}},
{"name": {"value": "@posthog/migrator3000-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/netdata-event-processing", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/nextjs", "operator": "=="}, "version": {"value": "0.0.3", "operator": "=="}},
{"name": {"value": "@posthog/nextjs-config", "operator": "=="}, "version": {"value": "1.5.1", "operator": "=="}},
{"name": {"value": "@posthog/nuxt", "operator": "=="}, "version": {"value": "1.2.9", "operator": "=="}},
{"name": {"value": "@posthog/pagerduty-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/piscina", "operator": "=="}, "version": {"value": "3.2.1", "operator": "=="}},
{"name": {"value": "@posthog/plugin-contrib", "operator": "=="}, "version": {"value": "0.0.6", "operator": "=="}},
{"name": {"value": "@posthog/plugin-server", "operator": "=="}, "version": {"value": "1.10.8", "operator": "=="}},
{"name": {"value": "@posthog/plugin-unduplicates", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/postgres-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/react-rrweb-player", "operator": "=="}, "version": {"value": "1.1.4", "operator": "=="}},
{"name": {"value": "@posthog/rrdom", "operator": "=="}, "version": {"value": "0.0.31", "operator": "=="}},
{"name": {"value": "@posthog/rrweb", "operator": "=="}, "version": {"value": "0.0.31", "operator": "=="}},
{"name": {"value": "@posthog/rrweb-player", "operator": "=="}, "version": {"value": "0.0.31", "operator": "=="}},
{"name": {"value": "@posthog/rrweb-record", "operator": "=="}, "version": {"value": "0.0.31", "operator": "=="}},
{"name": {"value": "@posthog/rrweb-replay", "operator": "=="}, "version": {"value": "0.0.19", "operator": "=="}},
{"name": {"value": "@posthog/rrweb-snapshot", "operator": "=="}, "version": {"value": "0.0.31", "operator": "=="}},
{"name": {"value": "@posthog/rrweb-utils", "operator": "=="}, "version": {"value": "0.0.31", "operator": "=="}},
{"name": {"value": "@posthog/sendgrid-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/siphash", "operator": "=="}, "version": {"value": "1.1.2", "operator": "=="}},
{"name": {"value": "@posthog/snowflake-export-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/taxonomy-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/twilio-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/twitter-followers-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/url-normalizer-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/variance-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@posthog/web-dev-server", "operator": "=="}, "version": {"value": "1.0.5", "operator": "=="}},
{"name": {"value": "@posthog/wizard", "operator": "=="}, "version": {"value": "1.18.1", "operator": "=="}},
{"name": {"value": "@posthog/zendesk-plugin", "operator": "=="}, "version": {"value": "0.0.8", "operator": "=="}},
{"name": {"value": "@postman/csv-parse", "operator": "=="}, "version": {"value": "4.0.3", "operator": "=="}},
{"name": {"value": "@postman/csv-parse", "operator": "=="}, "version": {"value": "4.0.5", "operator": "=="}},
{"name": {"value": "@postman/final-node-keytar", "operator": "=="}, "version": {"value": "7.9.1", "operator": "=="}},
{"name": {"value": "@postman/final-node-keytar", "operator": "=="}, "version": {"value": "7.9.2", "operator": "=="}},
{"name": {"value": "@trefox/sleekshop-js", "operator": "=="}, "version": {"value": "0.1.6", "operator": "=="}},
{"name": {"value": "@voiceflow/nestjs-mongodb", "operator": "=="}, "version": {"value": "1.3.2", "operator": "=="}},
{"name": {"value": "@voiceflow/nestjs-rate-limit", "operator": "=="}, "version": {"value": "1.3.2", "operator": "=="}},
{"name": {"value": "@voiceflow/nestjs-rate-limit", "operator": "=="}, "version": {"value": "1.3.3", "operator": "=="}},
{"name": {"value": "@voiceflow/nestjs-redis", "operator": "=="}, "version": {"value": "1.3.1", "operator": "=="}},
{"name": {"value": "@voiceflow/nestjs-redis", "operator": "=="}, "version": {"value": "1.3.2", "operator": "=="}},
{"name": {"value": "@voiceflow/nestjs-timeout", "operator": "=="}, "version": {"value": "1.3.1", "operator": "=="}},
{"name": {"value": "@voiceflow/npm-package-json-lint-config", "operator": "=="}, "version": {"value": "1.1.1", "operator": "=="}},
{"name": {"value": "@voiceflow/openai", "operator": "=="}, "version": {"value": "3.2.2", "operator": "=="}},
{"name": {"value": "@voiceflow/openai", "operator": "=="}, "version": {"value": "3.2.3", "operator": "=="}},
{"name": {"value": "@voiceflow/pino", "operator": "=="}, "version": {"value": "6.11.3", "operator": "=="}},
{"name": {"value": "@voiceflow/pino", "operator": "=="}, "version": {"value": "6.11.4", "operator": "=="}},
{"name": {"value": "@voiceflow/pino-pretty", "operator": "=="}, "version": {"value": "4.4.1", "operator": "=="}},
{"name": {"value": "@voiceflow/pino-pretty", "operator": "=="}, "version": {"value": "4.4.2", "operator": "=="}},
{"name": {"value": "@voiceflow/prettier-config", "operator": "=="}, "version": {"value": "1.10.1", "operator": "=="}},
{"name": {"value": "@voiceflow/react-chat", "operator": "=="}, "version": {"value": "1.65.4", "operator": "=="}},
{"name": {"value": "@voiceflow/runtime", "operator": "=="}, "version": {"value": "1.29.1", "operator": "=="}},
{"name": {"value": "@voiceflow/runtime", "operator": "=="}, "version": {"value": "1.29.2", "operator": "=="}},
{"name": {"value": "@voiceflow/runtime-client-js", "operator": "=="}, "version": {"value": "1.17.2", "operator": "=="}},
{"name": {"value": "@voiceflow/runtime-client-js", "operator": "=="}, "version": {"value": "1.17.3", "operator": "=="}},
{"name": {"value": "@voiceflow/sdk-runtime", "operator": "=="}, "version": {"value": "1.43.1", "operator": "=="}},
{"name": {"value": "@voiceflow/sdk-runtime", "operator": "=="}, "version": {"value": "1.43.2", "operator": "=="}},
{"name": {"value": "@voiceflow/secrets-provider", "operator": "=="}, "version": {"value": "1.9.2", "operator": "=="}},
{"name": {"value": "@voiceflow/semantic-release-config", "operator": "=="}, "version": {"value": "1.4.1", "operator": "=="}},
{"name": {"value": "@voiceflow/serverless-plugin-typescript", "operator": "=="}, "version": {"value": "2.1.7", "operator": "=="}},
{"name": {"value": "@voiceflow/serverless-plugin-typescript", "operator": "=="}, "version": {"value": "2.1.8", "operator": "=="}},
{"name": {"value": "@voiceflow/slate-serializer", "operator": "=="}, "version": {"value": "1.7.3", "operator": "=="}},
{"name": {"value": "@voiceflow/slate-serializer", "operator": "=="}, "version": {"value": "1.7.4", "operator": "=="}},
{"name": {"value": "@voiceflow/stitches-react", "operator": "=="}, "version": {"value": "2.3.2", "operator": "=="}},
{"name": {"value": "@voiceflow/stitches-react", "operator": "=="}, "version": {"value": "2.3.3", "operator": "=="}},
{"name": {"value": "@voiceflow/storybook-config", "operator": "=="}, "version": {"value": "1.2.2", "operator": "=="}},
{"name": {"value": "@voiceflow/storybook-config", "operator": "=="}, "version": {"value": "1.2.3", "operator": "=="}},
{"name": {"value": "@voiceflow/stylelint-config", "operator": "=="}, "version": {"value": "1.1.1", "operator": "=="}},
{"name": {"value": "@voiceflow/test-common", "operator": "=="}, "version": {"value": "2.1.1", "operator": "=="}},
{"name": {"value": "@voiceflow/test-common", "operator": "=="}, "version": {"value": "2.1.2", "operator": "=="}},
{"name": {"value": "@voiceflow/tsconfig", "operator": "=="}, "version": {"value": "1.12.1", "operator": "=="}},
{"name": {"value": "@voiceflow/tsconfig-paths", "operator": "=="}, "version": {"value": "1.1.4", "operator": "=="}},
{"name": {"value": "@voiceflow/tsconfig-paths", "operator": "=="}, "version": {"value": "1.1.5", "operator": "=="}},
{"name": {"value": "@voiceflow/utils-designer", "operator": "=="}, "version": {"value": "1.74.20", "operator": "=="}},
{"name": {"value": "@voiceflow/verror", "operator": "=="}, "version": {"value": "1.1.4", "operator": "=="}},
{"name": {"value": "@voiceflow/vite-config", "operator": "=="}, "version": {"value": "2.6.2", "operator": "=="}},
{"name": {"value": "@voiceflow/vite-config", "operator": "=="}, "version": {"value": "2.6.3", "operator": "=="}},
{"name": {"value": "@voiceflow/vitest-config", "operator": "=="}, "version": {"value": "1.10.2", "operator": "=="}},
{"name": {"value": "@voiceflow/vitest-config", "operator": "=="}, "version": {"value": "1.10.3", "operator": "=="}},
{"name": {"value": "@voiceflow/voice-types", "operator": "=="}, "version": {"value": "2.10.58", "operator": "=="}},
{"name": {"value": "@voiceflow/voice-types", "operator": "=="}, "version": {"value": "2.10.59", "operator": "=="}},
{"name": {"value": "@voiceflow/voiceflow-types", "operator": "=="}, "version": {"value": "3.32.45", "operator": "=="}},
{"name": {"value": "@voiceflow/voiceflow-types", "operator": "=="}, "version": {"value": "3.32.46", "operator": "=="}},
{"name": {"value": "@voiceflow/widget", "operator": "=="}, "version": {"value": "1.7.18", "operator": "=="}},
{"name": {"value": "@voiceflow/widget", "operator": "=="}, "version": {"value": "1.7.19", "operator": "=="}},
{"name": {"value": "@vucod/email", "operator": "=="}, "version": {"value": "0.0.3", "operator": "=="}},
{"name": {"value": "@zapier/ai-actions", "operator": "=="}, "version": {"value": "0.1.18", "operator": "=="}},
{"name": {"value": "@zapier/ai-actions", "operator": "=="}, "version": {"value": "0.1.19", "operator": "=="}},
{"name": {"value": "@zapier/ai-actions", "operator": "=="}, "version": {"value": "0.1.20", "operator": "=="}},
{"name": {"value": "@zapier/ai-actions-react", "operator": "=="}, "version": {"value": "0.1.12", "operator": "=="}},
{"name": {"value": "@zapier/ai-actions-react", "operator": "=="}, "version": {"value": "0.1.13", "operator": "=="}},
{"name": {"value": "@zapier/ai-actions-react", "operator": "=="}, "version": {"value": "0.1.14", "operator": "=="}},
{"name": {"value": "@zapier/babel-preset-zapier", "operator": "=="}, "version": {"value": "6.4.1", "operator": "=="}},
{"name": {"value": "@zapier/babel-preset-zapier", "operator": "=="}, "version": {"value": "6.4.2", "operator": "=="}},
{"name": {"value": "@zapier/babel-preset-zapier", "operator": "=="}, "version": {"value": "6.4.3", "operator": "=="}},
{"name": {"value": "@zapier/browserslist-config-zapier", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "@zapier/browserslist-config-zapier", "operator": "=="}, "version": {"value": "1.0.4", "operator": "=="}},
{"name": {"value": "@zapier/browserslist-config-zapier", "operator": "=="}, "version": {"value": "1.0.5", "operator": "=="}},
{"name": {"value": "@zapier/eslint-plugin-zapier", "operator": "=="}, "version": {"value": "11.0.3", "operator": "=="}},
{"name": {"value": "@zapier/eslint-plugin-zapier", "operator": "=="}, "version": {"value": "11.0.4", "operator": "=="}},
{"name": {"value": "@zapier/eslint-plugin-zapier", "operator": "=="}, "version": {"value": "11.0.5", "operator": "=="}},
{"name": {"value": "@zapier/mcp-integration", "operator": "=="}, "version": {"value": "3.0.1", "operator": "=="}},
{"name": {"value": "@zapier/mcp-integration", "operator": "=="}, "version": {"value": "3.0.2", "operator": "=="}},
{"name": {"value": "@zapier/mcp-integration", "operator": "=="}, "version": {"value": "3.0.3", "operator": "=="}},
{"name": {"value": "@zapier/secret-scrubber", "operator": "=="}, "version": {"value": "1.1.3", "operator": "=="}},
{"name": {"value": "@zapier/secret-scrubber", "operator": "=="}, "version": {"value": "1.1.4", "operator": "=="}},
{"name": {"value": "@zapier/secret-scrubber", "operator": "=="}, "version": {"value": "1.1.5", "operator": "=="}},
{"name": {"value": "@zapier/spectral-api-ruleset", "operator": "=="}, "version": {"value": "1.9.1", "operator": "=="}},
{"name": {"value": "@zapier/spectral-api-ruleset", "operator": "=="}, "version": {"value": "1.9.2", "operator": "=="}},
{"name": {"value": "@zapier/spectral-api-ruleset", "operator": "=="}, "version": {"value": "1.9.3", "operator": "=="}},
{"name": {"value": "@zapier/stubtree", "operator": "=="}, "version": {"value": "0.1.2", "operator": "=="}},
{"name": {"value": "@zapier/stubtree", "operator": "=="}, "version": {"value": "0.1.3", "operator": "=="}},
{"name": {"value": "@zapier/stubtree", "operator": "=="}, "version": {"value": "0.1.4", "operator": "=="}},
{"name": {"value": "@zapier/zapier-sdk", "operator": "=="}, "version": {"value": "0.15.5", "operator": "=="}},
{"name": {"value": "@zapier/zapier-sdk", "operator": "=="}, "version": {"value": "0.15.6", "operator": "=="}},
{"name": {"value": "@zapier/zapier-sdk", "operator": "=="}, "version": {"value": "0.15.7", "operator": "=="}},
{"name": {"value": "ai-crowl-shield", "operator": "=="}, "version": {"value": "1.0.7", "operator": "=="}},
{"name": {"value": "arc-cli-fc", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "asciitranslator", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "asyncapi-preview", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "asyncapi-preview", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "atrix", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "atrix-mongoose", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "automation_model", "operator": "=="}, "version": {"value": "1.0.491", "operator": "=="}},
{"name": {"value": "avvvatars-vue", "operator": "=="}, "version": {"value": "1.1.2", "operator": "=="}},
{"name": {"value": "axios-builder", "operator": "=="}, "version": {"value": "1.2.1", "operator": "=="}},
{"name": {"value": "axios-cancelable", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "axios-cancelable", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "axios-timed", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "axios-timed", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "medusa-plugin-product-reviews-kvy", "operator": "=="}, "version": {"value": "0.0.4", "operator": "=="}},
{"name": {"value": "medusa-plugin-zalopay", "operator": "=="}, "version": {"value": "0.0.40", "operator": "=="}},
{"name": {"value": "mod10-check-digit", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "mon-package-react-typescript", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "my-saeed-lib", "operator": "=="}, "version": {"value": "0.1.1", "operator": "=="}},
{"name": {"value": "n8n-nodes-tmdb", "operator": "=="}, "version": {"value": "0.5.1", "operator": "=="}},
{"name": {"value": "n8n-nodes-vercel-ai-sdk", "operator": "=="}, "version": {"value": "0.1.7", "operator": "=="}},
{"name": {"value": "n8n-nodes-viral-app", "operator": "=="}, "version": {"value": "0.2.5", "operator": "=="}},
{"name": {"value": "nanoreset", "operator": "=="}, "version": {"value": "7.0.1", "operator": "=="}},
{"name": {"value": "nanoreset", "operator": "=="}, "version": {"value": "7.0.2", "operator": "=="}},
{"name": {"value": "next-circular-dependency", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "next-circular-dependency", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "next-simple-google-analytics", "operator": "=="}, "version": {"value": "1.1.1", "operator": "=="}},
{"name": {"value": "next-simple-google-analytics", "operator": "=="}, "version": {"value": "1.1.2", "operator": "=="}},
{"name": {"value": "next-styled-nprogress", "operator": "=="}, "version": {"value": "1.0.4", "operator": "=="}},
{"name": {"value": "next-styled-nprogress", "operator": "=="}, "version": {"value": "1.0.5", "operator": "=="}},
{"name": {"value": "ngx-useful-swiper-prosenjit", "operator": "=="}, "version": {"value": "9.0.2", "operator": "=="}},
{"name": {"value": "ngx-wooapi", "operator": "=="}, "version": {"value": "12.0.1", "operator": "=="}},
{"name": {"value": "nitro-graphql", "operator": "=="}, "version": {"value": "1.5.12", "operator": "=="}},
{"name": {"value": "nitro-kutu", "operator": "=="}, "version": {"value": "0.1.1", "operator": "=="}},
{"name": {"value": "nitrodeploy", "operator": "=="}, "version": {"value": "1.0.8", "operator": "=="}},
{"name": {"value": "nitroping", "operator": "=="}, "version": {"value": "0.1.1", "operator": "=="}},
{"name": {"value": "normal-store", "operator": "=="}, "version": {"value": "1.3.1", "operator": "=="}},
{"name": {"value": "normal-store", "operator": "=="}, "version": {"value": "1.3.2", "operator": "=="}},
{"name": {"value": "normal-store", "operator": "=="}, "version": {"value": "1.3.3", "operator": "=="}},
{"name": {"value": "normal-store", "operator": "=="}, "version": {"value": "1.3.4", "operator": "=="}},
{"name": {"value": "nuxt-keycloak", "operator": "=="}, "version": {"value": "0.2.2", "operator": "=="}},
{"name": {"value": "obj-to-css", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "obj-to-css", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "okta-react-router-6", "operator": "=="}, "version": {"value": "5.0.1", "operator": "=="}},
{"name": {"value": "open2internet", "operator": "=="}, "version": {"value": "0.1.1", "operator": "=="}},
{"name": {"value": "orbit-boxicons", "operator": "=="}, "version": {"value": "2.1.3", "operator": "=="}},
{"name": {"value": "orbit-nebula-draw-tools", "operator": "=="}, "version": {"value": "1.0.10", "operator": "=="}},
{"name": {"value": "orbit-nebula-editor", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "orbit-soap", "operator": "=="}, "version": {"value": "0.43.13", "operator": "=="}},
{"name": {"value": "orchestrix", "operator": "=="}, "version": {"value": "12.1.2", "operator": "=="}},
{"name": {"value": "package-tester", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "parcel-plugin-asset-copier", "operator": "=="}, "version": {"value": "1.1.2", "operator": "=="}},
{"name": {"value": "parcel-plugin-asset-copier", "operator": "=="}, "version": {"value": "1.1.3", "operator": "=="}},
{"name": {"value": "pdf-annotation", "operator": "=="}, "version": {"value": "0.0.2", "operator": "=="}},
{"name": {"value": "pergel", "operator": "=="}, "version": {"value": "0.13.2", "operator": "=="}},
{"name": {"value": "pergeltest", "operator": "=="}, "version": {"value": "0.0.25", "operator": "=="}},
{"name": {"value": "piclite", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "pico-uid", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "pico-uid", "operator": "=="}, "version": {"value": "1.0.4", "operator": "=="}},
{"name": {"value": "pkg-readme", "operator": "=="}, "version": {"value": "1.1.1", "operator": "=="}},
{"name": {"value": "poper-react-sdk", "operator": "=="}, "version": {"value": "0.1.2", "operator": "=="}},
{"name": {"value": "posthog-docusaurus", "operator": "=="}, "version": {"value": "2.0.6", "operator": "=="}},
{"name": {"value": "posthog-js", "operator": "=="}, "version": {"value": "1.297.3", "operator": "=="}},
{"name": {"value": "posthog-node", "operator": "=="}, "version": {"value": "4.18.1", "operator": "=="}},
{"name": {"value": "posthog-node", "operator": "=="}, "version": {"value": "5.13.3", "operator": "=="}},
{"name": {"value": "posthog-plugin-hello-world", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "posthog-react-native", "operator": "=="}, "version": {"value": "4.11.1", "operator": "=="}},
{"name": {"value": "posthog-react-native", "operator": "=="}, "version": {"value": "4.12.5", "operator": "=="}},
{"name": {"value": "posthog-react-native-session-replay", "operator": "=="}, "version": {"value": "1.2.2", "operator": "=="}},
{"name": {"value": "prime-one-table", "operator": "=="}, "version": {"value": "0.0.19", "operator": "=="}},
{"name": {"value": "prompt-eng", "operator": "=="}, "version": {"value": "1.0.50", "operator": "=="}},
{"name": {"value": "prompt-eng-server", "operator": "=="}, "version": {"value": "1.0.18", "operator": "=="}},
{"name": {"value": "puny-req", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "quickswap-ads-list", "operator": "=="}, "version": {"value": "1.0.33", "operator": "=="}},
{"name": {"value": "quickswap-default-staking-list", "operator": "=="}, "version": {"value": "1.0.11", "operator": "=="}},
{"name": {"value": "quickswap-default-staking-list-address", "operator": "=="}, "version": {"value": "1.0.55", "operator": "=="}},
{"name": {"value": "quickswap-default-token-list", "operator": "=="}, "version": {"value": "1.5.16", "operator": "=="}},
{"name": {"value": "quickswap-router-sdk", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "quickswap-sdk", "operator": "=="}, "version": {"value": "3.0.44", "operator": "=="}},
{"name": {"value": "quickswap-smart-order-router", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "quickswap-token-lists", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "quickswap-v2-sdk", "operator": "=="}, "version": {"value": "2.0.1", "operator": "=="}},
{"name": {"value": "ra-auth-firebase", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "ra-data-firebase", "operator": "=="}, "version": {"value": "1.0.7", "operator": "=="}},
{"name": {"value": "ra-data-firebase", "operator": "=="}, "version": {"value": "1.0.8", "operator": "=="}},
{"name": {"value": "react-component-taggers", "operator": "=="}, "version": {"value": "0.1.9", "operator": "=="}},
{"name": {"value": "react-data-to-export", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "react-element-prompt-inspector", "operator": "=="}, "version": {"value": "0.1.18", "operator": "=="}},
{"name": {"value": "react-favic", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "react-hook-form-persist", "operator": "=="}, "version": {"value": "3.0.1", "operator": "=="}},
{"name": {"value": "react-hook-form-persist", "operator": "=="}, "version": {"value": "3.0.2", "operator": "=="}},
{"name": {"value": "react-jam-icons", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "react-jam-icons", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "react-keycloak-context", "operator": "=="}, "version": {"value": "1.0.8", "operator": "=="}},
{"name": {"value": "react-keycloak-context", "operator": "=="}, "version": {"value": "1.0.9", "operator": "=="}},
{"name": {"value": "react-library-setup", "operator": "=="}, "version": {"value": "0.0.6", "operator": "=="}},
{"name": {"value": "react-linear-loader", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "react-micromodal.js", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "react-micromodal.js", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "react-native-datepicker-modal", "operator": "=="}, "version": {"value": "1.3.1", "operator": "=="}},
{"name": {"value": "react-native-datepicker-modal", "operator": "=="}, "version": {"value": "1.3.2", "operator": "=="}},
{"name": {"value": "react-native-email", "operator": "=="}, "version": {"value": "2.1.1", "operator": "=="}},
{"name": {"value": "react-native-email", "operator": "=="}, "version": {"value": "2.1.2", "operator": "=="}},
{"name": {"value": "react-native-fetch", "operator": "=="}, "version": {"value": "2.0.1", "operator": "=="}},
{"name": {"value": "react-native-fetch", "operator": "=="}, "version": {"value": "2.0.2", "operator": "=="}},
{"name": {"value": "react-native-get-pixel-dimensions", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "react-native-get-pixel-dimensions", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "react-native-google-maps-directions", "operator": "=="}, "version": {"value": "2.1.2", "operator": "=="}},
{"name": {"value": "react-native-jam-icons", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "react-native-jam-icons", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "react-native-log-level", "operator": "=="}, "version": {"value": "1.2.1", "operator": "=="}},
{"name": {"value": "react-native-log-level", "operator": "=="}, "version": {"value": "1.2.2", "operator": "=="}},
{"name": {"value": "react-native-modest-checkbox", "operator": "=="}, "version": {"value": "3.3.1", "operator": "=="}},
{"name": {"value": "react-native-modest-storage", "operator": "=="}, "version": {"value": "2.1.1", "operator": "=="}},
{"name": {"value": "react-native-phone-call", "operator": "=="}, "version": {"value": "1.2.1", "operator": "=="}},
{"name": {"value": "react-native-phone-call", "operator": "=="}, "version": {"value": "1.2.2", "operator": "=="}},
{"name": {"value": "react-native-retriable-fetch", "operator": "=="}, "version": {"value": "2.0.1", "operator": "=="}},
{"name": {"value": "react-native-retriable-fetch", "operator": "=="}, "version": {"value": "2.0.2", "operator": "=="}},
{"name": {"value": "react-native-use-modal", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "react-native-view-finder", "operator": "=="}, "version": {"value": "1.2.1", "operator": "=="}},
{"name": {"value": "react-native-view-finder", "operator": "=="}, "version": {"value": "1.2.2", "operator": "=="}},
{"name": {"value": "react-native-websocket", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "react-native-websocket", "operator": "=="}, "version": {"value": "1.0.4", "operator": "=="}},
{"name": {"value": "react-native-worklet-functions", "operator": "=="}, "version": {"value": "3.3.3", "operator": "=="}},
{"name": {"value": "react-packery-component", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "react-qr-image", "operator": "=="}, "version": {"value": "1.1.1", "operator": "=="}},
{"name": {"value": "react-scrambled-text", "operator": "=="}, "version": {"value": "1.0.4", "operator": "=="}},
{"name": {"value": "rediff", "operator": "=="}, "version": {"value": "1.0.5", "operator": "=="}},
{"name": {"value": "rediff-viewer", "operator": "=="}, "version": {"value": "0.0.7", "operator": "=="}},
{"name": {"value": "redux-forge", "operator": "=="}, "version": {"value": "2.5.3", "operator": "=="}},
{"name": {"value": "redux-router-kit", "operator": "=="}, "version": {"value": "1.2.2", "operator": "=="}},
{"name": {"value": "redux-router-kit", "operator": "=="}, "version": {"value": "1.2.3", "operator": "=="}},
{"name": {"value": "redux-router-kit", "operator": "=="}, "version": {"value": "1.2.4", "operator": "=="}},
{"name": {"value": "revenuecat", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "rollup-plugin-httpfile", "operator": "=="}, "version": {"value": "0.2.1", "operator": "=="}},
{"name": {"value": "sa-company-registration-number-regex", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "sa-company-registration-number-regex", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "sa-id-gen", "operator": "=="}, "version": {"value": "1.0.4", "operator": "=="}},
{"name": {"value": "sa-id-gen", "operator": "=="}, "version": {"value": "1.0.5", "operator": "=="}},
{"name": {"value": "samesame", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "scgs-capacitor-subscribe", "operator": "=="}, "version": {"value": "1.0.11", "operator": "=="}},
{"name": {"value": "scgsffcreator", "operator": "=="}, "version": {"value": "1.0.5", "operator": "=="}},
{"name": {"value": "schob", "operator": "=="}, "version": {"value": "1.0.3", "operator": "=="}},
{"name": {"value": "selenium-session", "operator": "=="}, "version": {"value": "1.0.5", "operator": "=="}},
{"name": {"value": "selenium-session-client", "operator": "=="}, "version": {"value": "1.0.4", "operator": "=="}},
{"name": {"value": "set-nested-prop", "operator": "=="}, "version": {"value": "2.0.1", "operator": "=="}},
{"name": {"value": "solomon-api-stories", "operator": "=="}, "version": {"value": "1.0.2", "operator": "=="}},
{"name": {"value": "solomon-v3-stories", "operator": "=="}, "version": {"value": "1.15.6", "operator": "=="}},
{"name": {"value": "solomon-v3-ui-wrapper", "operator": "=="}, "version": {"value": "1.6.1", "operator": "=="}},
{"name": {"value": "zapier-scripts", "operator": "=="}, "version": {"value": "7.8.3", "operator": "=="}},
{"name": {"value": "zapier-scripts", "operator": "=="}, "version": {"value": "7.8.4", "operator": "=="}},
{"name": {"value": "zuper-cli", "operator": "=="}, "version": {"value": "1.0.1", "operator": "=="}},
{"name": {"value": "zuper-sdk", "operator": "=="}, "version": {"value": "1.0.57", "operator": "=="}},
{"name": {"value": "zuper-stream", "operator": "=="}, "version": {"value": "2.0.9", "operator": "=="}}
]
}

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
