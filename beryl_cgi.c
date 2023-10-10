#include <berylscript.h>

#include <assert.h>
#include <string.h>
#include <limits.h>

#include <stdio.h>

#define REQUIRE(x) { if(!x) { err = BERYL_ERR("Requirement failure"); goto ERR; } }

#define FN(name, arity, fn) { arity, false, name, sizeof(name) - 1, fn }

#define DEF_FN(name, arity) \
static struct i_val name##_callback(const struct i_val *args, i_size n_args); \
static struct beryl_external_fn name##_fn = FN(#name, arity, name##_callback); \
static struct i_val name##_callback(const struct i_val *args, i_size n_args)

#define SIMPLE_HTML_BLOCK(name, block_name) DEF_FN(name, 1) { \
	(void) n_args; \
	fputs("<" block_name ">", stdout); \
	struct i_val res; \
	if(BERYL_TYPEOF(args[0]) == TYPE_STR) { \
		beryl_print_i_val(stdout, args[0]); \
		res = BERYL_NULL; \
	} else { \
		res = beryl_call(args[0], NULL, 0, true); \
	} \
	\
	if(BERYL_TYPEOF(res) == TYPE_ERR) \
		return res; \
	fputs("</" block_name ">", stdout); \
	return res; \
}

DEF_FN(div, 1) {
	(void) n_args;
	
	fputs("<div>", stdout);
	struct i_val res = beryl_call(args[0], NULL, 0, true);
	if(BERYL_TYPEOF(res) == TYPE_ERR)
		return res;
	fputs("</div>", stdout);
	return res;
}

SIMPLE_HTML_BLOCK(section, "section")

SIMPLE_HTML_BLOCK(p, "p")

DEF_FN(link, 2) {
	(void) n_args;
	fputs("<a href=\"", stdout);
	beryl_print_i_val(stdout, args[1]);
	fputs("\">", stdout);
	beryl_print_i_val(stdout, args[0]);
	fputs("</a>", stdout);
	return BERYL_NULL;
}


DEF_FN(h, 2) {
	(void) n_args;
	fputs("<h", stdout);
	beryl_print_i_val(stdout, args[0]);
	putc('>', stdout);
	
	struct i_val res;
	if(BERYL_TYPEOF(args[1]) == TYPE_STR) {
		beryl_print_i_val(stdout, args[1]);
		res = BERYL_NULL;
	} else {
		res = beryl_call(args[1], NULL, 0, true);
	}

	if(BERYL_TYPEOF(res) != TYPE_ERR) {
		fputs("</h", stdout);
		beryl_print_i_val(stdout, args[0]);
		putc('>', stdout);
	}
	
	return res;
}
//SIMPLE_HTML_BLOCK(h, "h")

SIMPLE_HTML_BLOCK(html_table, "table")
SIMPLE_HTML_BLOCK(tr, "tr")
SIMPLE_HTML_BLOCK(th, "th")
SIMPLE_HTML_BLOCK(td, "td")

SIMPLE_HTML_BLOCK(body, "body")

DEF_FN(input, 3) {
	(void) n_args;
	fputs("<input type=\"", stdout);
	beryl_print_i_val(stdout, args[0]);
	fputs("\" id=\"", stdout);
	beryl_print_i_val(stdout, args[1]);
	fputs("\" name=\"", stdout);
	beryl_print_i_val(stdout, args[2]);
	fputs("\"/>", stdout);
	
	return BERYL_NULL;
}

DEF_FN(label, 2) {
	(void) n_args;
	struct i_val res;
	
	fputs("<label for=\"", stdout);
	beryl_print_i_val(stdout, args[0]);
	fputs("\">", stdout);
	
	if(BERYL_TYPEOF(args[1]) == TYPE_STR) { 
		beryl_print_i_val(stdout, args[1]);
		res = BERYL_NULL;
	} else {
		res = beryl_call(args[1], NULL, 0, true);
	}
	
	if(BERYL_TYPEOF(res) != TYPE_ERR)
		fputs("</label>", stdout);
	
	return res;
}

DEF_FN(select, 3) {
	(void) n_args;
	if(BERYL_TYPEOF(args[2]) != TYPE_ARRAY) {
		beryl_blame_arg(args[2]);
		return BERYL_ERR("Expected array as third argument for 'select', got '%0'");
	}
	
	fputs("<select name=\"", stdout);
	beryl_print_i_val(stdout, args[1]);
	fputs("\" id=\"", stdout);
	beryl_print_i_val(stdout, args[1]);
	fputs("\">", stdout);
	
	i_size len = BERYL_LENOF(args[2]);
	const struct i_val *a = beryl_get_raw_array(args[2]);
	
	for(i_size i = 0; i < len; i++) {
		fputs("<option value=\"", stdout);
		if(BERYL_TYPEOF(a[i]) == TYPE_ARRAY && BERYL_LENOF(a[i]) == 2) {
			const struct i_val *items = beryl_get_raw_array(a[i]);
			beryl_print_i_val(stdout, items[0]);
			fputs("\">", stdout);
			beryl_print_i_val(stdout, items[1]);
		} else {
			beryl_print_i_val(stdout, a[i]);
			fputs("\">", stdout);
			beryl_print_i_val(stdout, a[i]);
		}
		fputs("</option>", stdout);
	}
	
	fputs("</select>", stdout);
	
	return BERYL_NULL;
}

DEF_FN(submit, 1) {
	(void) n_args;
	fputs("<input type=\"submit\" value=\"", stdout);
	beryl_print_i_val(stdout, args[0]);
	fputs("\"/>", stdout);
	
	return BERYL_NULL;
}

DEF_FN(form, -4) {
	if(n_args % 2 != 1)
		return BERYL_ERR("'form' only takes an odd number of arguments");
	
	(void) n_args;
	fputs("<form action=\"", stdout);
	beryl_print_i_val(stdout, args[0]);
	fputs("\" method=\"", stdout);
	beryl_print_i_val(stdout, args[1]);
	fputs("\" ", stdout);
	
	for(i_size i = 2; i < n_args - 1; i += 2) {
		beryl_print_i_val(stdout, args[i]);
		fputs("=\"", stdout);
		assert(i + 1 < n_args - 1);
		beryl_print_i_val(stdout, args[i+1]);
		fputs("\" ", stdout);
	}
	
	fputs(">", stdout);
	
	struct i_val err;
	void *prev_scope = beryl_new_scope();
	
	REQUIRE(beryl_bind_name("input", sizeof("input") - 1, BERYL_EXT_FN(&input_fn), true));
	REQUIRE(beryl_bind_name("label", sizeof("label") - 1, BERYL_EXT_FN(&label_fn), true));
	REQUIRE(beryl_bind_name("select", sizeof("select") - 1, BERYL_EXT_FN(&select_fn), true));
	REQUIRE(beryl_bind_name("submit", sizeof("submit") - 1, BERYL_EXT_FN(&submit_fn), true));
	
	struct i_val res = beryl_call(args[n_args - 1], NULL, 0, true);
	if(BERYL_TYPEOF(res) == TYPE_ERR) {
		err = res;
		goto ERR;
	}
	
	fputs("</form>", stdout);
	beryl_restore_scope(prev_scope);
	return res;
	
	ERR:
	beryl_restore_scope(prev_scope);
	return err;
}

static struct i_val html_callback(const struct i_val *args, i_size n_args) {
	(void) n_args;
	
	struct i_val err;
	
	void *prev_scope = beryl_new_scope();
	
	REQUIRE(beryl_bind_name("div", sizeof("div") - 1, BERYL_EXT_FN(&div_fn), true));
	REQUIRE(beryl_bind_name("p", sizeof("p") - 1, BERYL_EXT_FN(&p_fn), true));
	REQUIRE(beryl_bind_name("link", sizeof("link") -1, BERYL_EXT_FN(&link_fn), true));
	REQUIRE(beryl_bind_name("h", sizeof("h") - 1, BERYL_EXT_FN(&h_fn), true));
	
	REQUIRE(beryl_bind_name("html-table", sizeof("html-table") - 1, BERYL_EXT_FN(&html_table_fn), true));
	REQUIRE(beryl_bind_name("tr", sizeof("tr") - 1, BERYL_EXT_FN(&tr_fn), true));
	REQUIRE(beryl_bind_name("th", sizeof("th") - 1, BERYL_EXT_FN(&th_fn), true));
	REQUIRE(beryl_bind_name("td", sizeof("td") - 1, BERYL_EXT_FN(&td_fn), true));
	
	REQUIRE(beryl_bind_name("form", sizeof("form") - 1, BERYL_EXT_FN(&form_fn), true));
	
	REQUIRE(beryl_bind_name("body", sizeof("body") - 1, BERYL_EXT_FN(&body_fn), true));
	
	REQUIRE(beryl_bind_name("section", sizeof("section") - 1, BERYL_EXT_FN(&section_fn), true));
	
	fputs("<html>", stdout);
	struct i_val res = beryl_call(args[0], NULL, 0, true);
	if(BERYL_TYPEOF(res) == TYPE_ERR) {
		err = res;
		goto ERR;
	}
	fputs("</html>", stdout);
	
	beryl_restore_scope(prev_scope);
	return res;
	
	ERR:
	beryl_restore_scope(prev_scope);
	return err;
}

DEF_FN(content_type, -2) {
	fputs("Content-Type: ", stdout);
	beryl_print_i_val(stdout, args[0]);
	
	for(size_t i = 1; i < n_args; i++) {
		fputs("; ", stdout);
		beryl_print_i_val(stdout, args[i]);
	}
	
	fputs("\r\n", stdout);
	return BERYL_NULL;
}

DEF_FN(content_type_html, 0) {
	(void) args, (void) n_args;
	
	fputs("Content-Type: text/html; charset=UTF-8\r\n", stdout);
	return BERYL_NULL;
}

DEF_FN(redirect, 1) {
	(void) n_args;
	
	fputs("Location: ", stdout);
	beryl_print_i_val(stdout, args[0]);
	fputs("\r\n", stdout);
	return BERYL_NULL;
}

DEF_FN(set_cookie, -3) {
	(void) n_args;
	fputs("Set-Cookie: ", stdout);
	beryl_print_i_val(stdout, args[0]);
	putc('=', stdout);
	beryl_print_i_val(stdout, args[1]);
	for(i_size i = 2; i < n_args; i++) {
		fputs("; ", stdout);
		beryl_print_i_val(stdout, args[i]);
	}
	fputs("\r\n", stdout);
	return BERYL_NULL;
}

static struct i_val headers_callback(const struct i_val *args, i_size n_args) {
	(void) n_args;
	
	struct i_val err;
	
	void *prev_scope = beryl_new_scope();
	
	REQUIRE(beryl_bind_name("content-type", sizeof("content-type") -1, BERYL_EXT_FN(&content_type_fn), true));
	REQUIRE(beryl_bind_name("content-type-html", sizeof("content-type-html") - 1, BERYL_EXT_FN(&content_type_html_fn), true));
	REQUIRE(beryl_bind_name("redirect", sizeof("redirect") - 1, BERYL_EXT_FN(&redirect_fn), true));
	REQUIRE(beryl_bind_name("set-cookie", sizeof("set-cookie") - 1, BERYL_EXT_FN(&set_cookie_fn), true));
	
	
	struct i_val res = beryl_call(args[0], NULL, 0, true);
	if(BERYL_TYPEOF(res) == TYPE_ERR) {
		err = res;
		goto ERR;
	}
	
	fputs("\r\n", stdout);
	
	beryl_restore_scope(prev_scope);
	return res;
	
	ERR:
	beryl_restore_scope(prev_scope);
	return err;
}

static unsigned hex_to_num(const char *str, size_t len) {
	unsigned n = 0;
	while(len--) {
		n *= 16;
		char c = *str;
		if(c >= '0' && c <= '9')
			n += c - '0';
		else if(c >= 'a' && c <= 'z')
			n += (c - 'a') + 10;
		else if(c >= 'A' && c <= 'Z')
			n += (c - 'A') + 10;
		
		str++;
	}
	
	return n;
}

static struct i_val escape_param_string(const char *str, const char *strend) {
	size_t max_size = strend - str;
	if(max_size > I_SIZE_MAX)
		return BERYL_NULL;
	
	char *buff = beryl_talloc(max_size);
	if(buff == NULL)
		return BERYL_NULL;
	
	char *buffp = buff;
	while(str < strend) {
		switch(*str) {
			case '+':
				*(buffp++) = ' ';
				str++;
				break;
				
			case '%':
				str++;
				if (strend - str >= 2) {
					unsigned n = hex_to_num(str, 2);
					if(n > CHAR_MAX)
						n = CHAR_MAX;
					*(buffp++) = (char) n;
				} else
					*(buffp++) = '%';
				str += 2;
				break;
			
			default:
				*(buffp++) = *(str++);
				break;
		}
	}
	
	struct i_val res = beryl_new_string(buffp - buff, buff);
	beryl_tfree(buff);
	return res;
}

static struct i_val parse_param_string(const char *str, size_t len, char param_delimiter, char key_val_delimiter, bool skip_spaces) {
	size_t delim_count = 0, param_count = 0;
	bool spaces_only = true;
	for(size_t i = 0; i < len; i++) { 
		if(str[i] != ' ')
			spaces_only = false;
		if(str[i] == param_delimiter)
			delim_count++;
		else if(str[i] == key_val_delimiter)
			param_count++;
	}
	
	if(spaces_only && skip_spaces) {
		struct i_val empty_table = beryl_new_table(0, false);
		if(BERYL_TYPEOF(empty_table) == TYPE_NULL)
			return BERYL_ERR("Out of memory");
		return empty_table;
	}
	
	size_t n_entries = delim_count + 1;
	if(n_entries > I_SIZE_MAX)
		return BERYL_ERR("Out of memory");
	
	if(n_entries != param_count)
		return BERYL_ERR("Malformed parameter string (wrong number of delimiters)");
	
	struct i_val table = beryl_new_table(n_entries, true);
	if(BERYL_TYPEOF(table) == TYPE_NULL)
		return BERYL_ERR("Out of memory");
	
	struct i_val key = BERYL_NULL;
	const char *str_end = str + len;
	bool parsing_key = true;
	const char *token_begin = NULL;
	for(const char *c = str; c < str_end; c++) {
		if(*c == ' ' && skip_spaces)
			continue;
		else if(*c == key_val_delimiter) {
			if(!parsing_key) {
				beryl_release(table);
				return BERYL_ERR("Malformed parameter string (unexpected key-value delimiter)");
			}
			if(token_begin == NULL) // I.e it's zero length like if x=foo;=bar (""=bar)
				key = BERYL_CONST_STR("");
			else {
				key = beryl_new_string(c - token_begin, token_begin);
				if(BERYL_TYPEOF(key) == TYPE_NULL) {
					beryl_release(table);
					return BERYL_ERR("Out of memory");
				}
			}
			token_begin = NULL;
			parsing_key = false;
		} else if(*c == param_delimiter) {
			if(parsing_key) {
				beryl_release(table);
				return BERYL_ERR("Malformed parameter string (unexpected parameter delimiter)");
			}
			assert(BERYL_TYPEOF(key) == TYPE_STR);
			
			struct i_val val;
			if(token_begin == NULL)
				val = BERYL_CONST_STR("");
			else {
				//val = beryl_new_string(c - token_begin, token_begin);
				val = escape_param_string(token_begin, c);
				if(BERYL_TYPEOF(val) == TYPE_NULL) {
					beryl_release(table);
					return BERYL_ERR("Out of memory");
				}
			}
			token_begin = NULL;
			parsing_key = true;
			
			beryl_table_insert(&table, key, val, true);
			beryl_release(key);
			beryl_release(val);
		} else if(token_begin == NULL)
			token_begin = c;
	}
	
	if(!parsing_key) {
		struct i_val val;
		if(token_begin == NULL)
			val = BERYL_CONST_STR("");
		else {
			val = escape_param_string(token_begin, str_end);
			if(BERYL_TYPEOF(val) == TYPE_NULL) {
				beryl_release(table);
				return BERYL_ERR("Out of memory");
			}
		}
		
		beryl_table_insert(&table, key, val, true);
		beryl_release(key);
		beryl_release(val);
	}
	
	return table;
}

static struct i_val parse_cookies_callback(const struct i_val *args, i_size n_args) {
	(void) n_args;
	
	if(BERYL_TYPEOF(args[0]) == TYPE_NULL) {
		struct i_val res = beryl_new_table(0, false);
		if(BERYL_TYPEOF(res) == TYPE_NULL)
			return BERYL_ERR("Out of memory");
		return res;
	} else if(BERYL_TYPEOF(args[0]) == TYPE_STR) {
		struct i_val res =  parse_param_string(beryl_get_raw_str(&args[0]), BERYL_LENOF(args[0]), ';', '=', true);
		if(BERYL_TYPEOF(res) == TYPE_ERR)
			beryl_blame_arg(args[0]);
		return res;
	} else
		return BERYL_ERR("Expected string or null as argument for 'parse-cookies'");

}

static struct i_val parse_url_parameters_callback(const struct i_val *args, i_size n_args) {
	(void) n_args;
	
	if(BERYL_TYPEOF(args[0]) == TYPE_NULL) {
		struct i_val res = beryl_new_table(0, false);
		if(BERYL_TYPEOF(res) == TYPE_NULL)
			return BERYL_ERR("Out of memory");
		return res;
	} else if(BERYL_TYPEOF(args[0]) == TYPE_STR) {
		struct i_val res = parse_param_string(beryl_get_raw_str(&args[0]), BERYL_LENOF(args[0]), '&', '=', false);
		if(BERYL_TYPEOF(res) == TYPE_ERR)
			beryl_blame_arg(args[0]);
		return res;
	} else
		return BERYL_ERR("Expected string or null as argument for 'parse-url-parameters'");
}

static bool loaded = false;

static struct i_val lib_val;

#define LENOF(a) (sizeof(a)/sizeof(a[0]))

#define REQUIRED_MAJOR_VER "0"
#define REQUIRED_SMAJOR_VER "0"

static void init_lib() {
	static struct beryl_external_fn fns[] = {
		FN("html", 1, html_callback),
		FN("headers", 1, headers_callback),
		FN("parse-cookies", 1, parse_cookies_callback),
		FN("parse-url-parameters", 1, parse_url_parameters_callback)
	};
	
	struct i_val table = beryl_new_table(LENOF(fns), true);
	if(BERYL_TYPEOF(table) == TYPE_NULL) {
		lib_val = BERYL_ERR("Out of memory");
		return;
	}
	
	for(size_t i = 0; i < LENOF(fns); i++) {
		beryl_table_insert(&table, BERYL_STATIC_STR(fns[i].name, fns[i].name_len), BERYL_EXT_FN(&fns[i]), false);
	}
	
	lib_val = table;
}

struct i_val beryl_lib_load() {
	bool ok_version = BERYL_LIB_CHECK_VERSION("0", "0");
	if(!ok_version) {
		return BERYL_ERR("Library `BerylCGI` only works for version 0:0:x");
	}

	if(!loaded) {
		init_lib();
		loaded = true;
	}
	return beryl_retain(lib_val);
}
