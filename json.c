#include <jansson.h>
#include <stdio.h>
#include <yara/modules.h>
#include <yara/mem.h>

#define MODULE_NAME json

int module_initialize(YR_MODULE* module) {
    return ERROR_SUCCESS;
}


int module_finalize(YR_MODULE* module) {
    return ERROR_SUCCESS;
}

int json_add_element(const char* name, json_t *element, YR_OBJECT *model_object);

int json_add_object(const char* name, json_t* object, YR_OBJECT* model_object) {
    size_t size;
    const char* element_name;
    json_t* element;

    size = json_object_size(object);

    fprintf(stderr,"JSON Object of %lld pair(s):\n", (long long)size);
    fprintf(stderr,"object Key: \"%s\"\n", name);

    YR_OBJECT* structure;
    YR_OBJECT* array;
    FAIL_ON_ERROR(yr_object_create(
			    OBJECT_TYPE_DICTIONARY, name, model_object, &array));
    FAIL_ON_ERROR(yr_object_create(
			    OBJECT_TYPE_STRUCTURE, name, array, &structure));

    json_object_foreach(object, element_name, element) {
        fprintf(stderr,"JSON Key: \"%s\"\n", element_name);
        json_add_element(element_name, element, structure);
    }
    return ERROR_SUCCESS;
}

int json_add_array(const char* name, json_t* jarray, YR_OBJECT* model_object) {
    size_t i;
    size_t size = json_array_size(jarray);
    char *element_name;
    int buflen;
    buflen = strlen(name)+16;
    element_name = yr_malloc(buflen);

    fprintf(stderr,"JSON Array of %lld element(s):\n", (long long)size);
    fprintf(stderr,"array Key: \"%s\"\n", name);
    
    YR_OBJECT* structure;
    YR_OBJECT* array;
    FAIL_ON_ERROR(yr_object_create(
			    OBJECT_TYPE_ARRAY, name, model_object, &array));
    FAIL_ON_ERROR(yr_object_create(
			    OBJECT_TYPE_STRUCTURE, name, array, &structure));

    for (i = 0; i < size; i++) {
	snprintf(element_name, buflen, "%s[%li]", name, i);
        json_add_element((const char *)element_name, json_array_get(jarray, i), structure);
    }
    yr_free(element_name);
    return ERROR_SUCCESS;
}

int json_add_string(const char* name, json_t* element, YR_OBJECT* model_object) {
    const char* value;
    fprintf(stderr,"key %s JSON String: \"%s\"\n", name, json_string_value(element));
    FAIL_ON_ERROR(
        yr_object_create(OBJECT_TYPE_STRING, name, model_object, NULL));
    value = json_string_value(element);
    set_string(value, model_object, name, NULL);
    return ERROR_SUCCESS;
}

int json_add_integer(const char *name, json_t *element, YR_OBJECT *model_object) {
    fprintf(stderr,"JSON Integer: \"%" JSON_INTEGER_FORMAT "\"\n", json_integer_value(element));
    FAIL_ON_ERROR(
        yr_object_create(OBJECT_TYPE_INTEGER, name, model_object, NULL));
    set_integer(json_integer_value(element), model_object, name, NULL);
    return ERROR_SUCCESS;
}

int json_add_real(const char *name, json_t *element, YR_OBJECT *model_object) {
    printf("JSON Real: %f\n", json_real_value(element));
    FAIL_ON_ERROR(
        yr_object_create(OBJECT_TYPE_FLOAT, name, model_object, NULL));
    set_float(json_real_value(element), model_object, name, NULL);
    return ERROR_SUCCESS;
}

int json_add_true(const char *name, json_t *element, YR_OBJECT *model_object) {
    FAIL_ON_ERROR(
        yr_object_create(OBJECT_TYPE_INTEGER, name, model_object, NULL));
    set_integer(1, model_object, name, NULL);
    fprintf(stderr,"JSON True\n");
    return ERROR_SUCCESS;
}

int json_add_false(const char *name, json_t *element, YR_OBJECT *model_object) {
    FAIL_ON_ERROR(
        yr_object_create(OBJECT_TYPE_INTEGER, name, model_object, NULL));
    set_integer(0, model_object, name, NULL);
    fprintf(stderr,"JSON False\n");
    return ERROR_SUCCESS;
}

int json_add_null(const char *name, json_t *element, YR_OBJECT *model_object) {
    FAIL_ON_ERROR(
        yr_object_create(OBJECT_TYPE_INTEGER, name, model_object, NULL));
    set_integer(0, model_object, name, NULL);
    fprintf(stderr,"JSON Null\n");
    return ERROR_SUCCESS;
}

int json_add_element(const char* name, json_t *element, YR_OBJECT *model_object) {
    switch (json_typeof(element)) {
        case JSON_OBJECT:
    	    FAIL_ON_ERROR(json_add_object(name, element, model_object));
            break;
        case JSON_ARRAY:
            FAIL_ON_ERROR(json_add_array(name, element, model_object));
            break;
        case JSON_STRING:
            FAIL_ON_ERROR(json_add_string(name, element, model_object));
            break;
        case JSON_INTEGER:
            FAIL_ON_ERROR(json_add_integer(name, element, model_object));
            break;
        case JSON_REAL:
            FAIL_ON_ERROR(json_add_real(name, element, model_object));
            break;
        case JSON_TRUE:
            FAIL_ON_ERROR(json_add_true(name, element, model_object));
            break;
        case JSON_FALSE:
            FAIL_ON_ERROR(json_add_false(name, element, model_object));
            break;
        case JSON_NULL:
            FAIL_ON_ERROR(json_add_null(name, element, model_object));
            break;
        default:
            fprintf(stderr, "unrecognized JSON type %d\n", json_typeof(element));
	    return(ERROR_WRONG_TYPE);
    }
    return(ERROR_SUCCESS);
}

int module_load(YR_SCAN_CONTEXT* context, YR_OBJECT* module_object, void* module_data, size_t module_data_size) {
    YR_MEMORY_BLOCK* block = first_memory_block(context);
    const uint8_t* block_data = block->fetch_data(block);

    json_error_t json_error;
    json_t* json = json_loads((const char*) block_data, 0, &json_error);

    if(!json) {
        fprintf(stderr, "JSON error: on line %d: %s\n", json_error.line, json_error.text);
        return ERROR_INVALID_FORMAT;
    }
    module_object->data = json;

    /* create object */
    json_add_element("val", json, module_object);

    return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object) {
    return ERROR_SUCCESS;
}

define_function(key_value) {
    json_t* json = module()->data;
    if (json == NULL) {
        return ERROR_INVALID_FILE;
    }

    char* key = string_argument(1);
    char* value = string_argument(2);

    json_t* json_value = json_object_get(json, key);
    if (json_value == NULL) {
        return_integer(YR_UNDEFINED);
    }

    const char* json_val = json_string_value(json_value);
    if (strcmp(json_val, value) == 0) {
        return_integer(1);
    }

    return_integer(0);
}


define_function(has_key) {
    json_t* json = module()->data;
    if (json == NULL) {
        return ERROR_INVALID_FILE;
    }

    char* key = string_argument(1);
    json_t* json_value = json_object_get(json, key);

    if (json_value == NULL) {
        return_integer(0);
    }
    return_integer(1);
}


define_function(has_key_r) {
    json_t* json = module()->data;
    if (json == NULL) {
        return ERROR_INVALID_FILE;
    }

    YR_SCAN_CONTEXT* context = scan_context();
    RE* key_regex = regexp_argument(1);

    void *iter = json_object_iter(json);
    while (iter) {
        const char *json_key = json_object_iter_key(iter);
        if (yr_re_match(context, key_regex, json_key) > 0) {
            return_integer(1);
        }
    }

    return_integer(0);
}


begin_declarations;
    begin_struct("val");
    end_struct("val");

    declare_function("kv", "ss", "i", key_value);
    declare_function("has_key", "s", "i", has_key);
    declare_function("has_key", "r", "i", has_key_r);

end_declarations;

#undef MODULE_NAME
