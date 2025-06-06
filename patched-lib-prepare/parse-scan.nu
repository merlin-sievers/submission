#!/bin/nu

def main [json: path] {
	open $json |
	where {|e| [zlib] has $e.product} |
	select product cve_number paths |
	update paths { |row| $row.paths | split row ", " } |
	update paths { |row| $row.paths | split row ".extracted" | first} |
	flatten paths |
	uniq |
	group-by --to-table product cve_number |
	each { |g| {product: $g.product, cve_number: $g.cve_number, count: ($g.items | length) } }
	# | save cves.json
	# open $json | where {|e| [zlib libpng libxml openssl sqlite libtiff] has $e.product} | select product cve_number | uniq | save cves.json
}
