/*! \brief YAML - Yet Another Markup Language
    YAML -- человекочитаемый формат сериализации данных, концептуально близкий к языкам разметки, но ориентированный на удобство ввода-вывода типичных структур данных многих языков программирования.

    \see http://www.yaml.org/spec/1.2/spec.html

 */
#include "yaml.h"

/*! \brief декодирование строки содержащей символы вида \xFF
 */
static char* yaml_string_decode(char * s, int length)
{
    if (s[0]=='"') s++, length--;
    while(length>0 && s[length-1]==' ')length--;
    if (length>0 && s[length-1]=='"') length--;
    GString* str = g_string_new_len(NULL, length);
    int run_len=0;
    int i;
    for (i=0;i<length; i++){
        if (s[i]=='\\' && s[i+1]=='x' && g_ascii_isxdigit(s[i+2]) && g_ascii_isxdigit(s[i+3])) {
            if (run_len>0) g_string_append_len(str, &s[i-run_len], run_len);

            unsigned char ch = 0;
            if ('0'<=s[i+2] && s[i+2]<='9') ch = (s[i+2] - '0')<<4;
            else if ('A'<=s[i+2] && s[i+2]<='F') ch = (s[i+2] - 'A'+10)<<4;
            else if ('a'<=s[i+2] && s[i+2]<='f') ch = (s[i+2] - 'A'+10)<<4;

            if ('0'<=s[i+3] && s[i+3]<='9') ch |= (s[i+3] - '0');
            else if ('A'<=s[i+3] && s[i+3]<='F') ch |= (s[i+3] - 'A'+10);
            else if ('a'<=s[i+3] && s[i+3]<='f') ch |= (s[i+3] - 'A'+10);
            i+=3; run_len=0;
            g_string_append_c(str, ch);
            //printf("ch=\\x%02X\n", ch);
        } else
            run_len++;
    }
    if (run_len>0) g_string_append_len(str, &s[i-run_len], run_len);
    return g_string_free(str, FALSE);
}
/*! \brief Выделить строку
    \param sep разделитель строк, преформатированные строки '|'=>'\n', '>'=>' ';
 */
static char* yaml_string(char * s, char** tail, int parent_offset, char sep)
{
    GString* str = g_string_new(NULL);
    while (s[0]!='\0'){
        int offset=0, length=0;
        while (s[offset]==' ' && offset<parent_offset+2) offset++;
        if (offset<parent_offset+2) break;
        while (s[offset+length]!='\0' && s[offset+length]!='\n') length++;
        if (length==0) {// пустая строка - перевод строки
            g_string_append_c(str, '\n');
        } else {
            if (str->len) g_string_append_c(str, sep);// преформатированный текст, разделитель ''
            g_string_append_len(str, &s[offset], length);
        }
        s+= offset+length;
        if (s[0]=='\n') s++;
    }
    if(tail) *tail = s;
    return g_string_free(str, FALSE);
}

/*! \brief Создание узла дерева
 */
static GNode* yaml_element_new(char* s, char** tail, int parent_offset)
{
    Yaml_element* elem=NULL;
    if (g_ascii_isalnum(s[0]) || s[0]=='"' || s[0]=='_') {
        elem = g_slice_new(Yaml_element);
        elem->value=NULL;
        char* name = s;
        if (s[0]=='"') {
            name++,s++;
            while(s[0]!='\0' && !(s[0]=='"' && s[1]==':')) { s++;  }
        } else
            while(s[0]!='\0' && s[0]!=':' && s[0]!='\n') { s++;  }
        char ch = s[0]; s[0] = '\0';
        elem->id = g_quark_from_string(name);
        s[0] = ch;
        if (ch) s++;
        if (ch=='"' && s[0]==':') s++;
        while (s[0]==' ') s++;
        char* value = s;
        while(s[0]!='\0' /*&& s[0]!='\r'*/ && s[0]!='\n') { s++;  }
        if (value != s) {
            if (value[0]=='[') {// набор параметров
            } else
            if (value[0]=='"') {// строка содержит спец. символы

                elem->value = yaml_string_decode(value, s-value);
            } else
            if (value[0]=='|') {// строка с форматированием
                if (s[0]=='\n') s++;
                elem->value = yaml_string(s, &s, parent_offset, '\n');
            } else
            if (value[0]=='>') {
                if (s[0]=='\n') s++;
                elem->value = yaml_string(s, &s, parent_offset, ' ');
            } else
                elem->value = g_strndup(value, s - value);
        } else
            elem->value = NULL;
        //if (s[0]=='\r') s++;
        if (s[0]=='\n') s++;

    }
    if (tail) *tail = s;
    return g_node_new(elem);
}

/*! \brief Разбор строки в формате YAML
 */
GNode* yaml_parse(char* s, char ** tail)
{
    //GNode* node;
    GNode* parent = g_node_new(NULL);
    GNode* node=NULL;
    int parent_offset=0;
//    static int lineno=1;
    while (s[0]!='\0'){
            //printf("l:%d %X %-.10s\n", lineno++, (unsigned int)s, s);
        int offset=0;// отступ вначале строки
        while(s[0]==' ') {s++; offset++; }
        if (offset==0 && s[0]=='-' && s[1]=='-' && s[2]=='-') {
            s+=3;
            while (s[0]!='\0' && s[0]!='\n') s++;
            if (s[0]=='\n') s++;
            break;
        }
        if (offset==0 && s[0]=='#') {// comment
            s+=2;
            while (s[0]!='\0' && s[0]!='\n') s++;
            if (s[0]=='\n') s++;
            continue;
        }
        if (offset>parent_offset) {
            parent_offset=offset;
            if (node) parent = node;
        } else
        while (offset<parent_offset) { // добавить на тот же уровень
            parent = parent->parent;
            parent_offset-=2;
        }

        if (s[0]=='-' && s[1]==' ') {// элемент списка
            s+=2;
                // get data
            node = yaml_element_new(s, &s, offset);
            g_node_append(parent, node);
        } else
        //if (g_ascii_isalpha(s[0]))
        {
            // выделить имя, если после имени :
            node = yaml_element_new(s, &s, offset);
            g_node_append(parent, node);
        }
    }
    if (tail) *tail = s;
    return g_node_get_root(parent);
}

typedef void (*YamlCallback)(GNode*, int);
static inline void yaml_children_foreach(GNode* node, YamlCallback cb, int offset){
    if (node){
        GNode* child = node->children;
        while (child){
            cb(child, offset);
            child=child->next;
        }
    }
}
static void yaml_element_print(GNode* node, int offset)
{
    Yaml_element* elem = node->data;
    g_print("%*s%s: %s\n", offset, "", g_quark_to_string(elem->id), elem->value?elem->value:"");
    yaml_children_foreach(node, yaml_element_print, offset+2);
}
static void yaml_element_free(GNode* node, int offset)
{
    Yaml_element* elem = node->data;
    if (elem->value) g_free(elem->value); elem->value=NULL;
    g_slice_free(Yaml_element, elem);
    yaml_children_foreach(node, yaml_element_free, offset+2);

}
void yaml_print(GNode* node)
{
    int offset=0;
    yaml_children_foreach(node, yaml_element_print, offset);
}
void yaml_free(GNode* node)
{
    int offset=0;
    yaml_children_foreach(node, yaml_element_free, offset);
    g_node_destroy(node);
}
GNode* yaml_find(GNode* parent, char* tag_name)
{
    GQuark tag_id = g_quark_from_string(tag_name);
    GNode* node = parent->children;
    while(node){
        Yaml_element* elem = node->data;
        if (elem->id == tag_id) break;
        node = node->next;
    }
    return node;
}
char* yaml_attr(GNode* parent, char* attr_name)
{
    GQuark tag_id = g_quark_from_string(attr_name);
    GNode* node = parent->children;
    while(node){
        Yaml_element* elem = node->data;
        if (elem->id == tag_id) {
            return elem->value;
        }
        node = node->next;
    }
    return NULL;
}
