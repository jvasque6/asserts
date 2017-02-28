from fluidasserts.service import http
from fluidasserts.service import http_ssl
from fluidasserts.service import moddns

server = 'fluid.la'
http.is_version_visible(server)
http_ssl.is_cert_cn_not_equal_to_site(server)
http_ssl.is_cert_inactive(server)
http_ssl.is_cert_validity_lifespan_unsafe(server)
http_ssl.is_pfs_disabled(server)
http_ssl.is_sslv3_enabled(server)
http_ssl.is_tlsv1_enabled(server)
moddns.has_cache_poison(server, 'ns-79.awsdns-09.com.')
