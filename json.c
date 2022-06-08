#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <yara/modules.h>
#include <yara/mem.h>
#include <json-c/json.h>

#define MODULE_NAME json

int module_initialize(YR_MODULE* module) {
    return ERROR_SUCCESS;
}


int module_finalize(YR_MODULE* module) {
    return ERROR_SUCCESS;
}

int module_load(YR_SCAN_CONTEXT* context, YR_OBJECT* module_object, void* module_data, size_t module_data_size) {
    YR_MEMORY_BLOCK* block = first_memory_block(context);
    const uint8_t* block_data = block->fetch_data(block);

    enum json_tokener_error json_error;
    struct json_object* json = json_tokener_parse_verbose((const char *)block_data, &json_error);
      
    if(!json) {
      fprintf(stderr, "JSON error: %s\n", json_tokener_error_desc(json_error));
        return ERROR_INVALID_FORMAT;
    }
    module_object->data = json;

    return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object) {
    return ERROR_SUCCESS;
}

define_function(parsedate) {
    struct tm *tmp;

    setenv("DATEMSK", "./date-mask", 1);
    char* datetime_string = string_argument(1);
    tmp = getdate(datetime_string);

    if (tmp == NULL) {
        printf("getdate %s failed; getdate_err = %d\n",
             datetime_string, getdate_err);
        return_integer(YR_UNDEFINED);
    }

    return_integer(mktime(tmp));
}

#define ARG_TYPE_STRING char* arg1 = string_argument(2)
#define ARG_TYPE_INT    int64_t arg1 = integer_argument(2)
#define ARG_TYPE_FLOAT  double arg1 = float_argument(2)
#define RET_TYPE_STRING return_string(string)
#define RET_TYPE_INT    return_integer(atoi(string))
#define RET_TYPE_FLOAT  return_float(atof(string))

#define make_query_function(NAME, ARG2_DEF, RET_VAL)   \
define_function(NAME) {                                \
                                                       \
    json_object* root = module()->data;                \
    if (root == NULL) {                                \
        return ERROR_INVALID_FILE;                     \
    }                                                  \
                                                       \
    char* path = string_argument(1);                   \
    ARG2_DEF;                                          \
                                                       \
    json_object* obj;                                  \
                                                       \
    int rc = json_pointer_getf(root, &obj, path, arg1);\
                                                       \
    const char *string = json_object_get_string(obj);  \
                                                       \
    if (rc == 0) {                                     \
        RET_VAL;                                       \
    } else {                                           \
        return_string(YR_UNDEFINED);                   \
    }                                                  \
}

make_query_function(query_s_s, ARG_TYPE_STRING, RET_TYPE_STRING)
make_query_function(query_d_s, ARG_TYPE_INT, RET_TYPE_STRING)
make_query_function(query_f_s, ARG_TYPE_FLOAT, RET_TYPE_STRING)
make_query_function(query_s_i, ARG_TYPE_STRING, RET_TYPE_INT)
make_query_function(query_d_i, ARG_TYPE_INT, RET_TYPE_INT)
make_query_function(query_f_i, ARG_TYPE_FLOAT, RET_TYPE_INT)
make_query_function(query_s_f, ARG_TYPE_STRING, RET_TYPE_FLOAT)
make_query_function(query_d_f, ARG_TYPE_INT, RET_TYPE_FLOAT)
make_query_function(query_f_f, ARG_TYPE_FLOAT, RET_TYPE_FLOAT)

/* Declare all permutations of query.  
 *
 * First arg is 'path', a string starting with /, with 
 * object names separated by / digging deeper into the json
 * structure.  path can contain a single paramerer: %s, %d, or %f
 *
 * Second arg is the parameter, a string, integer, or float.
 *
 * declare_function allows overloading the function name based on
 * the args, but not the return value, hence query_s is
 * the version which returns a string. 
 */
begin_declarations;
    declare_function("parsedate", "s", "i", parsedate);

    declare_function("query", "s", "s", query_s_s);
    declare_function("query", "ss", "s", query_s_s);
    declare_function("query", "si", "s", query_d_s);
    declare_function("query", "sf", "s", query_f_s);

    declare_function("query_s", "s", "s", query_s_s);
    declare_function("query_s", "ss", "s", query_s_s);
    declare_function("query_s", "si", "s", query_d_s);
    declare_function("query_s", "sf", "s", query_f_s);

    declare_function("query_i", "s", "i", query_s_i);
    declare_function("query_i", "ss", "i", query_s_i);
    declare_function("query_i", "si", "i", query_d_i);
    declare_function("query_i", "sf", "i", query_f_i);

    declare_function("query_f", "s", "f", query_s_f);
    declare_function("query_f", "ss", "f", query_s_f);
    declare_function("query_f", "si", "f", query_d_f);
    declare_function("query_f", "sf", "f", query_f_f);

end_declarations;

#undef MODULE_NAME
