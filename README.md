yara-json
------------

json.query(path, [arg]) → string
json.query_s(path, [arg]) → string  (synomym for json.query)
json.query_i(path, [arg]) → integer
json.query_f(path, [arg]) → float


Module to read a JSON file.  Entire file must be valid JSON.  Allows
conditions to query into this JSON using a "path" which must start
with a /.

The path string can contain a single %s, %d, or %f which consumes the
arg which must match that type.  If more than one arg is needed, the
module can easily be added to allow additional args.


Example rule:

```
import "json"

rule jsonrule {
	condition:
                json.query_i("/inquest/processor-output/%d/severity",0) >= 8
}
```
