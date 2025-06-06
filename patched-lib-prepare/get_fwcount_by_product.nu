#!/bin/nu

def main [json: path] {
	open $json |
	select product paths |
	update paths { |row| $row.paths | split row ", " } |
	flatten paths |
	update paths { |row| $row.paths | split row ".extracted" | first } |
	flatten paths |
	uniq |
	group-by product --to-table |
	each { |e| {product: $e.product, count: ($e.items | uniq | length) } } |
	sort-by count |
	save -f fwcount-by-product.json
}
