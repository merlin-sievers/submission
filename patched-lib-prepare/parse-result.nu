#!/bin/nu

def main [json: path] {
	open $json |
	where {|e| [zlib] has $e.product} |
	select product cve instances |
	flatten instances |
	each { |g| {product: $g.product, cve: $g.cve, affected: ($g.instances.affected_path) } } |
	group-by --to-table product cve |
	each { |g| {product: $g.product, cve: $g.cve, count: ($g.items | length) } }
	# | save cves.json
	# open $json | where {|e| [zlib libpng libxml openssl sqlite libtiff] has $e.product} | select product cve_number | uniq | save cves.json
}
