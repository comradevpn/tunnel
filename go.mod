module github.com/vpnhouse/tunnel

go 1.22.2

toolchain go1.22.6

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/getsentry/sentry-go v0.12.0
	github.com/go-chi/chi/v5 v5.0.7
	github.com/google/uuid v1.6.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/jmoiron/sqlx v1.3.4
	github.com/mattn/go-sqlite3 v1.14.10
	github.com/posener/h2conn v0.0.0-20231204025407-3997deeca0f0
	github.com/prometheus/client_golang v1.12.1
	github.com/rubenv/sql-migrate v1.0.0
	github.com/spf13/afero v1.8.0
	github.com/stretchr/testify v1.8.4
	github.com/vishvananda/netlink v1.1.0
	github.com/vpnhouse/api v0.0.0-20240916134854-020f48ada450
	github.com/vpnhouse/common-lib-go v0.0.0-20250131032737-6c42ed381051
	github.com/vpnhouse/iprose-go v0.2.0
	go.uber.org/multierr v1.10.0
	go.uber.org/zap v1.25.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20211230205640-daad0b7ba671
	google.golang.org/grpc v1.44.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/hlandau/passlib.v1 v1.0.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/coredns/caddy v1.1.1 // indirect
	github.com/coredns/coredns v1.9.1 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/erwint/ttlcache v1.6.1 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-acme/lego/v4 v4.6.0 // indirect
	github.com/go-chi/cors v1.2.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/nftables v0.0.0-20221002140148-535f5eb8da79 // indirect
	github.com/miekg/dns v1.1.55 // indirect
	github.com/muesli/cache2go v0.0.0-20221011235721-518229cd8021 // indirect
	github.com/oschwald/maxminddb-golang v1.8.0 // indirect
	github.com/slok/go-http-metrics v0.10.0 // indirect
	go.etcd.io/etcd/client/v3 v3.5.2 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
)

require (
	github.com/BurntSushi/toml v0.4.1 // indirect
	github.com/DataDog/datadog-agent/pkg/obfuscate v0.0.0-20211129110424-6491aa3bf583 // indirect
	github.com/DataDog/datadog-go v4.8.2+incompatible // indirect
	github.com/DataDog/datadog-go/v5 v5.0.2 // indirect
	github.com/DataDog/sketches-go v1.0.0 // indirect
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/apparentlymart/go-cidr v1.1.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.1.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd/v22 v22.3.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/deepmap/oapi-codegen v1.9.1 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dnstap/golang-dnstap v0.4.0 // indirect
	github.com/dolthub/maphash v0.1.0 // indirect
	github.com/farsightsec/golang-framestream v0.3.0 // indirect
	github.com/flynn/go-shlex v0.0.0-20150515145356-3f9db97f8568 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.7 // indirect
	github.com/grpc-ecosystem/grpc-opentracing v0.0.0-20180507213350-8e809c8a8645 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/josharian/native v0.0.0-20200817173448-b6b71def0850 // indirect
	github.com/klauspost/compress v1.17.5 // indirect
	github.com/lxzan/gws v1.8.3 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/mdlayher/genetlink v1.1.0 // indirect
	github.com/mdlayher/netlink v1.4.2 // indirect
	github.com/mdlayher/socket v0.0.0-20211102153432-57e3fa563ecb // indirect
	github.com/opentracing-contrib/go-observer v0.0.0-20170622124052-a52f23424492 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/openzipkin-contrib/zipkin-go-opentracing v0.4.5 // indirect
	github.com/openzipkin/zipkin-go v0.4.0 // indirect
	github.com/philhofer/fwd v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.32.1 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8 // indirect
	github.com/tinylib/msgp v1.1.2 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	github.com/ziutek/mymysql v1.5.4 // indirect
	go.etcd.io/etcd/api/v3 v3.5.2 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.2 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/sync v0.6.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	golang.org/x/time v0.0.0-20211116232009-f0f3c7e86c11 // indirect
	golang.org/x/tools v0.6.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20211129173154-2dd424e2d808 // indirect
	google.golang.org/genproto v0.0.0-20220218161850-94dd64e39d7c // indirect
	gopkg.in/DataDog/dd-trace-go.v1 v1.36.2 // indirect
	gopkg.in/gorp.v1 v1.7.2 // indirect
	gopkg.in/hlandau/easymetric.v1 v1.0.0 // indirect
	gopkg.in/hlandau/measurable.v1 v1.0.1 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	honnef.co/go/tools v0.2.2 // indirect
)
