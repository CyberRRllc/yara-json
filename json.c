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

define_function(query_s_s) {
    json_object* root = module()->data;
    if (root == NULL) {
        return ERROR_INVALID_FILE;
    }

    char* path = string_argument(1);
    void* arg1 = string_argument(2);

    json_object* obj;

    int rc = json_pointer_getf(root, &obj, path, arg1);

    const char *string = json_object_get_string(obj);

    if (rc == 0) {
        return_string(string);
    } else {
        return_string(YR_UNDEFINED);
    }
}

define_function(query_d_s) {
    json_object* root = module()->data;
    if (root == NULL) {
        return ERROR_INVALID_FILE;
    }

    char* path = string_argument(1);
    int64_t arg1 = integer_argument(2);

    json_object* obj;

    int rc = json_pointer_getf(root, &obj, path, arg1);

    const char *string = json_object_get_string(obj);

    if (rc == 0) {
        return_string(string);
    } else {
        return_string(YR_UNDEFINED);
    }
}

define_function(query_f_s) {
    json_object* root = module()->data;
    if (root == NULL) {
        return ERROR_INVALID_FILE;
    }

    char* path = string_argument(1);
    double arg1 = float_argument(2);

    json_object* obj;

    int rc = json_pointer_getf(root, &obj, path, arg1);

    const char *string = json_object_get_string(obj);

    if (rc == 0) {
        return_string(string);
    } else {
        return_string(YR_UNDEFINED);
    }
}


define_function(query_s_i) {
    json_object* root = module()->data;
    if (root == NULL) {
        return ERROR_INVALID_FILE;
    }

    char* path = string_argument(1);
    void* arg1 = string_argument(2);

    json_object* obj;

    int rc = json_pointer_getf(root, &obj, path, arg1);

    const char *string = json_object_get_string(obj);

    if (rc == 0) {
        return_integer(atoi(string));
    } else {
        return_string(YR_UNDEFINED);
    }
}

define_function(query_d_i) {
    json_object* root = module()->data;
    if (root == NULL) {
        return ERROR_INVALID_FILE;
    }

    char* path = string_argument(1);
    int64_t arg1 = integer_argument(2);

    json_object* obj;

    int rc = json_pointer_getf(root, &obj, path, arg1);

    const char *string = json_object_get_string(obj);

    if (rc == 0) {
        return_integer(atoi(string));
    } else {
        return_string(YR_UNDEFINED);
    }
}

define_function(query_f_i) {
    json_object* root = module()->data;
    if (root == NULL) {
        return ERROR_INVALID_FILE;
    }

    char* path = string_argument(1);
    double arg1 = float_argument(2);

    json_object* obj;

    int rc = json_pointer_getf(root, &obj, path, arg1);

    const char *string = json_object_get_string(obj);

    if (rc == 0) {
        return_integer(atoi(string));
    } else {
        return_string(YR_UNDEFINED);
    }
}


define_function(query_s_f) {
    json_object* root = module()->data;
    if (root == NULL) {
        return ERROR_INVALID_FILE;
    }

    char* path = string_argument(1);
    void* arg1 = string_argument(2);

    json_object* obj;

    int rc = json_pointer_getf(root, &obj, path, arg1);

    const char *string = json_object_get_string(obj);

    if (rc == 0) {
        return_string(string);
    } else {
        return_string(YR_UNDEFINED);
    }
}

define_function(query_d_f) {
    json_object* root = module()->data;
    if (root == NULL) {
        return ERROR_INVALID_FILE;
    }

    char* path = string_argument(1);
    int64_t arg1 = integer_argument(2);

    json_object* obj;

    int rc = json_pointer_getf(root, &obj, path, arg1);

    const char *string = json_object_get_string(obj);

    if (rc == 0) {
        return_float(atof(string));
    } else {
        return_string(YR_UNDEFINED);
    }
}

define_function(query_f_f) {
    json_object* root = module()->data;
    if (root == NULL) {
        return ERROR_INVALID_FILE;
    }

    char* path = string_argument(1);
    double arg1 = float_argument(2);

    json_object* obj;

    int rc = json_pointer_getf(root, &obj, path, arg1);

    const char *string = json_object_get_string(obj);

    if (rc == 0) {
        return_float(atof(string));
    } else {
        return_string(YR_UNDEFINED);
    }
}



begin_declarations;
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
