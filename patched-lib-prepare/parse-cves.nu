#!/bin/nu

def main [json: path] {
	open $json |
    	select product cve_number paths |
	# where { |e| [zlib] has $e.product} |
    	update paths { |row|
                $row.paths
		| split row ", "
                # find { |part| $part =~ '.extracted' }
        } |
	uniq |
	update paths { |row| 
        	$row.paths 
		| split row ".extracted" | first
        	# find { |part| $part =~ '.extracted' }  
    	} |
	flatten paths |
	uniq
	# group-by --to-table paths  |
	# each { |g| {paths: $g.paths, cves: ($g.items | get cve_number | uniq), count: ($g.items | get cve_number | uniq | length)}}
}
