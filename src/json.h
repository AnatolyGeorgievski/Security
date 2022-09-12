/*! */
#ifndef JSON_H
#define JSON_H
#include <glib.h>
#include <stdint.h>
enum {
    JSON_NULL=0,
    JSON_OBJECT,
    JSON_ARRAY,
    JSON_STRING,
    JSON_DOUBLE,
    JSON_INT,
    JSON_BOOL,
    };
typedef struct _JsonNode JsonNode;
struct _JsonNode {
    int type;
    GQuark tag_id;
    union {
#if defined(__arm__)
// для 32 битных платформ
        uint32_t u;
        int32_t i;
        float f;
#else
        uint64_t u;
        int64_t i;
        double f;
#endif
        char* s;
        void* p;
        int b; // bool
        GSList* list;
    } value;
};

static inline JsonNode* json_new(int type)
{
    JsonNode* js = g_slice_new0(JsonNode);
    js->type = type;
    return js;
}
void      json_free(JsonNode* js);
JsonNode* json_value(char* s, char** tail, GError** error);

JsonNode* json_object_get(JsonNode* js, GQuark id);
/*! \brief удалить элемент из списка полей объекта */
static inline
JsonNode* json_object_append(JsonNode* parent, JsonNode* js)
{
    parent->value.list = g_slist_append(parent->value.list, js);
    return parent;
}

void json_to_string(JsonNode* js, GString* str, int offset);
// API совместимо с KeyFile
void json_set_id_integer(JsonNode* js, GQuark group_id, GQuark attr_id, int32_t);// тип int может отличаться для разных платформ
void json_set_id_double (JsonNode* js, GQuark group_id, GQuark attr_id, double);
void json_set_id_value  (JsonNode* js, GQuark group_id, GQuark attr_id, const char*);
void json_set_id_boolean(JsonNode* js, GQuark group_id, GQuark attr_id, int);

#endif // JSON_H
