#ifndef YAML_H_INCLUDED
#define YAML_H_INCLUDED

#include <glib.h>
typedef struct _Yaml_element Yaml_element;
struct _Yaml_element {
    GQuark id;
    char* value;
};
static inline GQuark yaml_tag(GNode* node){
    return ((Yaml_element*)node->data)->id;
}
static inline const char* yaml_key(GNode* node){
    Yaml_element* elem = node->data;
    return elem->id?g_quark_to_string(elem->id):NULL;
}

static inline char* yaml_value(GNode* node){
    return ((Yaml_element*)node->data)->value;
}
GNode* yaml_parse(char* s, char ** tail);
GNode* yaml_find(GNode* parent, char* tag_name);
char* yaml_attr(GNode* parent, char* attr_name);
void yaml_print(GNode* node);
void yaml_free(GNode* node);
#endif // YAML_H_INCLUDED
