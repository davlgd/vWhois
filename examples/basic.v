module main

import vwhois

fn main() {
	result := vwhois.lookup('davlgd.fr', vwhois.Config{})
	println(vwhois.format_text([result]))
}
