# Building & installing
First build the library:
```
make
```
Then install it (requires Beryl to be installed):
```
make install
```

# Basic usage
```
let cgi = require "~/cgi"

let req-method = getenv "REQUEST_METHOD"

if req-method == "GET" do
	cgi :headers do
		invoke content-type-html
	end
	
	cgi :html do
		h 1 "Hello world!"
		div do
			p "This is a hello world page!"
			link "CGI Library" "https://github.com/KarlAndr1/beryl-cgi"
		end
	end
end


```
