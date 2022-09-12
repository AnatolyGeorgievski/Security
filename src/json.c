/*! JSON (JavaScript Object Notation) разбор текстового формата

    \see [ECMA-404] The JSON Data Interchange Standard. <http://www.json.org/json-ru.html>
    \see [RFC 8259] The JavaScript Object Notation (JSON) Data Interchange Format, December 2017
    \see [RFC 7159] The JavaScript Object Notation (JSON) Data Interchange Format, March 2014
    <https://tools.ietf.org/html/rfc7159>
    \see [RFC 7396] JSON Merge Patch, October 2014
    \see [RFC 6901] JavaScript Object Notation (JSON) Pointer, April 2013
    \see [RFC 6902] JavaScript Object Notation (JSON) Patch, April 2013

Тестирование:
$ gcc -o test.exe json.c base64.c -lws2_32 `pkg-config --libs --cflags glib-2.0` -DTEST_JSON
 */
#include "json.h"
#include <string.h>
#include <stdlib.h>

/*!
    Исходим из нескольких приближений
    1) Файл загружен целиком в динамическую память
    2) Можно резать файл

    Бинарные данные произвольной длины положено передавать в кодировке base64Binary в форме строки
 */
/*! \brief освобождает память */
void json_free(JsonNode* js)
{
    if (js==NULL) return;
    if (js->type==JSON_ARRAY || js->type==JSON_OBJECT){
        if (js->value.list) {
            GSList* list= js->value.list;
            while (list){
                if (list->data) json_free((JsonNode*)list->data); //list->data = NULL;
                list = list->next;
            }
            g_slist_free(js->value.list);
            js->value.list=NULL;
        }
    } else
    if (js->type==JSON_STRING){
        if (js->value.s) {
            g_free(js->value.s);
            js->value.s = NULL;
        }
    }
    g_slice_free(JsonNode, js);
}
/*! \brief выделяет тег при разборе формата */
static GQuark json_tag_id(char* s, char** tail)
{
    GQuark id = 0;
    if(s[0]=='"'){
        s++;
        char* tag = s;
        while (s[0]!='"' && s[0]!='\0')s++;
        if (s[0]=='"') {
            *s++ ='\0';
            id = g_quark_from_string(tag);
            //*s++='"';
        }
    }
    if (tail)*tail=s;
    return id;
}
//! \todo копировать строку!
static char* json_string_value(char* s, char** tail)
{
    char* value = s;
    while (s[0]!='"'  && s[0]!='\0'){
        if(s[0]=='\\' && s[1]=='"') s+=2;
        else s++;
    }
    if(s[0]=='"') {
        s++;//*s++='\0';
    }
    *tail = s;
    return value;
}
/*! \brief выполнить разбор строки данных */
JsonNode *json_value(char* s, char** tail, GError** error)
{
    JsonNode* js = NULL;
    while (g_ascii_isspace(s[0]))s++;
    if (s[0]=='\0') goto do_exit;
    switch(*s++){
    case '"': {// начало строки или поля объекта
            js = json_new(JSON_STRING); // созданная строка
            char* str = json_string_value(s, &s);
            js->value.s = (s>str)?g_strndup(str, s - str-1):NULL;
        }
        break;
    case '[': {// массив
        js = json_new(JSON_ARRAY);
        GSList* list =NULL;
        while (g_ascii_isspace(s[0]))s++;
        while (s[0]!=']' && s[0]!='\0') {
            JsonNode* js_elem = json_value(s, &s, error);
            if (js_elem) {
                list = g_slist_append(list, js_elem);
            }
            if (s[0]==',') s++;
            else
                break;
            while (g_ascii_isspace(s[0]))s++;
        }
        js->value.list = list;
    } break;
    case '{': {// объект
        js = json_new(JSON_OBJECT);
        GSList* list = NULL;
        while(g_ascii_isspace(s[0])) s++;
        while (s[0]!='}' && s[0]!='\0') {
            GQuark tag_id = json_tag_id(s, &s); // без копирования строки, можно временно вставить символ конца строки
            while(g_ascii_isspace(s[0])) s++;
            if(s[0]==':') {
                s++;
                JsonNode* js_elem = json_value(s, &s, error);
                if (js_elem){
                    js_elem->tag_id = tag_id;
                    list = g_slist_append(list, js_elem);
                }
            } else {
                //error = g_error_new();
                break;
            }
            if (s[0]==',') s++;
            else
                break;
            while(g_ascii_isspace(s[0])) s++;
        }
        if(s[0]=='}')s++;
        js->value.list = list;
        // else err=;
    } break;
    case 't': {// true
        if (strncmp(s, "rue", 3)==0){
            js = json_new(JSON_BOOL);
            js->value.b = TRUE;
            s+=3;
        } //else err=;
    } break;
    case 'f': {// false
        if (strncmp(s, "alse", 4)==0){
        //if (((*(uint32_t*)s) ^ (*(uint32_t*)"alse"))==0){
            js = json_new(JSON_BOOL);
            js->value.b = FALSE;
            s+=4;
        }// else err=;

    } break;
    case 'n': {// null
        if (strncmp(s, "ull", 3)==0){
            js = json_new(JSON_NULL);
            s+=3;
        }// else err=;

    } break;
    case '-':// число со знаком
    case '0'...'9': {
            s--;
            char* ref = s;
            if (s[0]=='0' && s[1]=='x'){// не является частью стандарта, шестнадцатеричные числа
                ref+=2;
                js = json_new(JSON_INT);
                js->value.i = g_ascii_strtoll(ref, &s, 16);
                break;
            }
            if(s[0]=='-')s++;
            while (g_ascii_isdigit(s[0])) s++;
            if(s[0]=='.'){// вещественное число
                js = json_new(JSON_DOUBLE);
                js->value.f = g_ascii_strtod(ref, &s);
            } else {// целое число
                js = json_new(JSON_INT);
                js->value.i = g_ascii_strtoll(ref, &s, 10);
            }
    } break;
    default:
        break;
    }
    while (g_ascii_isspace(s[0]))s++;
do_exit:
    if(tail)*tail = s;
    return js;
}
/*! \brief с отступами и переносами строк */
void json_to_string(JsonNode* js, GString* str, int offset)
{
    if (js==NULL) { // проверить на практике, может быть плохая идея
        g_string_append(str, "null");
        return;
    }
    if (js->tag_id) g_string_append_printf(str, "%*s\"%s\":", offset, "",g_quark_to_string(js->tag_id));
    switch (js->type){
    case JSON_ARRAY: {
        GSList* list = js->value.list;
        g_string_append(str, "[\n");
        while (list) {
            json_to_string((JsonNode*)list->data, str, offset+2);
            g_string_append(str, ",\n");
            list = list->next;
        }
        g_string_append(str, "]");
    } break;
    case JSON_OBJECT: {
        GSList* list = js->value.list;
        g_string_append(str, "{\n");
        while (list) {
            json_to_string((JsonNode*)list->data, str, offset+2);
            g_string_append(str, ",\n");
            list = list->next;
        }
        g_string_append_printf(str, "%*s}", offset, "");
    } break;
    case JSON_NULL:
        g_string_append(str, "null");
        break;
    case JSON_BOOL:
        g_string_append(str, js->value.b!=0?"true":"false");
        break;
    case JSON_INT:
        g_string_append_printf(str, "%lld", js->value.i);
        break;
    case JSON_DOUBLE:
        g_string_append_printf(str, "%g", js->value.f);
        break;
    case JSON_STRING:
        g_string_append_printf(str, "\"%s\"", js->value.s);
        break;
    default:
        g_print("ERR:undefined type\n");
        break;
    }

}
/*! \brief получить элемент списка - по идентификатору */
static GSList* json_object_get_(GSList* list, GQuark tag_id)
{
    while (list){
        JsonNode* js = list->data;
        if (js->tag_id == tag_id){
            break;
        }
        list = list->next;
    }
    return list;
}
JsonNode* json_object_get (JsonNode* js, GQuark attr_id)
{
//    if (js==NULL || js->type!=JSON_OBJECT) return NULL;
    GSList *list = js->value.list;
    while (list) {
        js = list->data;
        if (/* js!=NULL && */js->tag_id == attr_id) {
            return js;
        }
        list = list->next;
    }
    return NULL;
}

/*! \brief выборка элемента структуры данных по пути
    \param id - список идентификаторов, заканчивается нулем

    \todo к элементам массива можно обратиться по номеру элемента

*/
#if 0
JsonNode* json_object_path(JsonNode* js, GQuark* id)
{
    while (*id!=0 && js) {
        if (js->type==JSON_OBJECT) {
            GSList* list = json_object_get_(js->value.list, *id++);
            js = list!=NULL? list->data: NULL;
        } else
        if (js->type==JSON_ARRAY) {
            GSList* list = g_slist_nth(js->value.list, *id++);
            js = list!=NULL? list->data: NULL;
        } else {
            return NULL;
        }
    }
    return js;
}
#endif // 0

/*! \brief удалить элемент из списка полей объекта */
static JsonNode* json_object_remove(JsonNode* parent, GQuark tag_id)
{
//    if (js==NULL || js->type!=JSON_OBJECT) return;
    GSList** prev = &parent->value.list;
    GSList* list = parent->value.list;
    while (list){
        JsonNode* js = list->data;
        if (js!=NULL && js->tag_id==tag_id) {
            break;
        }
        prev = &list->next;
        list = list->next;
    }
    if (list) {// элемент найден
        JsonNode* js = list->data;
        *prev = list->next;
//        list->next = NULL;
        g_slice_free(GSList, list);
        return js;
    }
    return NULL;
}

/*!
 define MergePatch(Target, Patch):
     if Patch is an Object:
       if Target is not an Object:
         Target = {} # Ignore the contents and set it to an empty Object
       for each Name/Value pair in Patch:
         if Value is null:
           if Name exists in Target:
             remove the Name/Value pair from Target
         else:
           Target[Name] = MergePatch(Target[Name], Value)
       return Target
     else:
       return Patch

   PATCH /my/resource HTTP/1.1
   Host: example.org
   Content-Type: application/merge-patch+json

   {
     "title": "Hello!",
     "phoneNumber": "+01-123-456-7890",
     "author": {
       "familyName": null
     },
     "tags": [ "example" ]
   }

 */

/*!
    \param patch - всегда объект JSON_OBJECT
При сращивании списков, если имена одинаковые, а это как определить?
{name:"dirname", children:{
    {id:"filename1", action:"create", mtime:"", etag:""},
    {id:"filename2", action:"create", mtime:"", etag:""},
    {id:"filename3", action:"create", mtime:"", etag:""},
    }
}
 */
void json_object_merge_patch(JsonNode* target, JsonNode* patch)
{
    GSList* list=patch->value.list;
    while (list){
        JsonNode* js = list->data;
        if(js->type==JSON_NULL){
            json_object_remove(target, js->tag_id);
            g_slice_free(JsonNode, js);// удалил
        } else {// операция замены
            GSList* node = target->value.list;//json_object_get(target, js->tag_id);
            while (node) {
                JsonNode* jn = node->data;
                if (/*jn!=NULL &&*/ jn->tag_id == js->tag_id) {
                    break;
                }
                node = node->next;
            }
            if (node) {
                JsonNode* jn = node->data;
                if (jn->type==JSON_OBJECT && js->type==JSON_OBJECT) {// сростить
                    json_object_merge_patch(jn, js);
                    g_slice_free(JsonNode, js);
                } else {// заменить
                    node->data = js;
                    json_free(jn);
                }
            } else {// добавить элемент
                target->value.list = g_slist_append(target->value.list, js);
            }
        }
        list = list->next;
    }
    g_slist_free(patch->value.list);
    patch->value.list = NULL;
}
/*!
    application/json-patch+json
*/
/*! для ускорения разбора полей, предполагаем что первый элемент member,
    если не найден элемент поиск ведется от начала списка
 */
/*! \brief пребразует элемент пути в идентификатор */
static GQuark json_path_tag(char* path, char**tail)
{
    if (path[0]=='/') path++;
    char* s = path;
    while (s[0] != '/' && s[0]!='\0' ) s++;
    char ch = s[0]; s[0] = '\0';
    GQuark id = g_quark_from_string(path);// если идентификатор не существует, то и элемента не найти
    s[0] = ch;
    if (tail) *tail = s;
    return id;
}
static int json_patch_opcode(JsonNode* parent, char* path, JsonNode* value, const char* opcode)
{
    GSList* list = parent->value.list;
    GSList* prev = NULL;
    if (parent->type == JSON_OBJECT) {// поиск элемента в объекте
        GQuark tag_id = json_path_tag(path, &path);
        g_print("OBJECT %s\n", g_quark_to_string(tag_id));
        if (value) value->tag_id = tag_id;
        while (list){
            JsonNode* js = list->data;
            if (js->tag_id == tag_id) {
                break;
            }
            prev = list;
            list = list->next;
        }
    } else
    if (parent->type == JSON_ARRAY) {// поиск элемента в массиве
        unsigned int nth = path[0]=='-'? ~0: atol(path);
        if (value) value->tag_id = 0;
        while (list!=NULL && nth){
            nth--;
            prev = list;
            list = list->next;
        }
    }
    // исполнение команд
    if (strcmp(opcode,"add")== 0) {// вставить сюда
        GSList * next = list;
        list = g_slice_new(GSList);
        //if (parent->type == JSON_OBJECT) value->tag_id =
        list->data = value;
        list->next = next;
        if (prev) {
            prev->next = list;
        } else {
            parent->value.list = list;
        }
    } else
    if (strcmp(opcode,"replace")== 0) { // заменить
        if (list) {
            JsonNode* js = list->data;
            list->data = value;
            json_free(js);
        }
    } else
    if (strcmp(opcode,"remove")== 0) { // исключить
        if (list) {
            GSList* next = list->next;
            // можно вернуть объект обратно
            json_free((JsonNode*) (list->data));
            g_slice_free(GSList, list);
            if (prev) {// исключить
                prev->next = next;
            } else { // исключимть с начала списка
                parent->value.list = next;
            }
        } else { // элемент не найден
        }
    } else
    if (strcmp(opcode,"test")== 0) {
        if (list) { // cуществует
            /// \todo сравнить json_compare сравнение строк, чисел, дат
        } else { // элемент не найден
        }
    }
    return 0;
}
static JsonNode* json_path_follow(JsonNode* parent, char* path, char** tail)
{
    if (path[0]=='/') path++; // пропускаем палку
    char* s = path;
    while (s[0]!='\0' && s[0]!='/') s++; // выделяем идентификатор или число
    if (tail) *tail = (s[0]=='\0')? NULL: s; // неразобранная часть пути
    if (s[0]=='\0') {
//        if (tail) *tail = path;
        return parent;
    }
    // иначе следует найти элемент с данным идентификатором
    GSList* list = parent->value.list;
    if (parent->type == JSON_OBJECT){
        char ch = s[0]; s[0] = '\0';
        GQuark tag_id = g_quark_try_string(path);
        s[0] = ch;
        if (tag_id==0) return NULL;// не найден
        while (list){
            JsonNode* js = list->data;
            if (js->tag_id == tag_id) {
                break;
            }
            list = list->next;
        }
    } else
    if (parent->type == JSON_ARRAY){
        unsigned int nth = atol(path);
        list = g_slist_nth(list, nth);
    } else { // не конструктивно,
        return NULL; // не найден
    }
    if (list) {// найден элемент списка
        return json_path_follow((JsonNode*)list->data, s, tail);
    }
    return NULL; // не найден
}
int json_patch (JsonNode* js, JsonNode* patch)
{
    GQuark id_op = g_quark_from_string("op");
    GQuark id_path = g_quark_from_string("path");
    GQuark id_value = g_quark_from_string("value");
    GSList* list = patch->value.list;
    GSList* sl_op = json_object_get_(list, id_op);
    if (list == sl_op) list = list->next;
    GSList* sl_path = json_object_get_(list, id_path);
    if (list == sl_path) list = list->next;
    const char* opcode = ((JsonNode*)(sl_op->data))->value.s;
    char* path = ((JsonNode*)(sl_path->data))->value.s;
    js = json_path_follow(js, path, &path); // найти последнего родителя и остаток пути
    g_print("PATH = %s OPCODE =%s\n", path, opcode);
    if (js==NULL) return 1;
    JsonNode* value = json_object_remove(patch, id_value);
    json_patch_opcode(js, path, value, opcode);
    return 0; // OK
}


#ifdef TEST_JSON_PATCH
char t1[] = "{\"foo\": \"bar\"}" ;
char p1[] = "{ \"op\": \"add\", \"path\": \"/baz\", \"value\": \"qux\" }";
char t2[] = "{ \"foo\": [ \"bar\", \"baz\" ] }";
char p2[] = "{ \"op\": \"add\", \"path\": \"/foo/1\", \"value\": \"qux\" }";
char t3[] = "{\"baz\": \"qux\",\"foo\": \"bar\"}";
char p3[] = "{ \"op\": \"remove\", \"path\": \"/baz\" }";
char t4[] = "{ \"foo\": [ \"bar\", \"qux\", \"baz\" ] }";
char p4[] = "{ \"op\": \"remove\", \"path\": \"/foo/1\" }";
char t5[] = "{ \"baz\": \"qux\", \"foo\": \"bar\" }";
char p5[] = "{ \"op\": \"replace\", \"path\": \"/baz\", \"value\": \"boo\" }";
char t6[] = "{ \"foo\": { \"bar\": \"baz\", \"waldo\": \"fred\"  },  \"qux\": { \"corge\": \"grault\"   } }";
char p6[] = "{ \"op\": \"move\", \"from\": \"/foo/waldo\", \"path\": \"/qux/thud\" }";
// A.10.  Adding a Nested Member Object
char t10[] = "{ \"foo\": \"bar\" }";
char p10[] = "{ \"op\": \"add\", \"path\": \"/child\", \"value\": { \"grandchild\": { } } }";
// A.11.  Ignoring Unrecognized Elements
char t11[] = "{ \"foo\": \"bar\" }";
char p11[] = "";
// A.12.  Adding to a Nonexistent Target
char t12[] = "{ \"foo\": \"bar\" }";
char p12[] = "{ \"op\": \"add\", \"path\": \"/baz/bat\", \"value\": \"qux\" }";
// A.16.  Adding an Array Value
char t16[] = "{ \"foo\": [\"bar\"] }";
char p16[] = "{ \"op\": \"add\", \"path\": \"/foo/-\", \"value\": [\"abc\", \"def\"] }";
int main(int argc, char**argv)
{
//    if (argc<3) return 0;
//    g_print("> %s\n", t1);
//    g_print("> %s\n", p1);
    JsonNode* js = json_value(t12, NULL, NULL);
    JsonNode* patch = json_value(p12, NULL, NULL);
    GString* str = g_string_new(NULL);
    json_to_string(js, str, 0);
    json_to_string(patch, str, 0);
    g_print("%s\n", str->str);
    int res = json_patch(js, patch);
    g_string_truncate(str,0);
    json_to_string(js, str, 0);
    g_print("%s\n", str->str);
    json_free(js);
    json_free(patch);
    return res;//json_patch(js, patch);
}
#endif // TEST_JSON_PATCH

#ifdef TEST_JSON
int main()
{
char* str1 =
"{\"access_token\":\"1DE731E8\",\n"
"\"token_type\":\"Bearer\",\n"
"\"expires_in\":3600,\n"
"\"refresh_token\":\"0EF398F4\",\n}";


char* str2 =
"{\".definitions\": {\n"
    "\"BACnetFileAccessMethod\":{"
        "\"$base\": \"Enumerated\","
        "\"$namedValues\": {"
            "\"recordAccess\":{ \"$base\":\"Unsigned\", \"value\":0 },"
            "\"streamAccess\":{ \"$base\":\"Unsigned\", \"value\":1 }"
        "}"
    "}"
"}";
    str1 = g_strdup(str2);
    JsonNode* js= json_value(str1, NULL, NULL);
    GString* str = g_string_sized_new(127);
    json_to_string(js, str, 0);
    g_print("%s\n", str->str);


    JsonNode* elem = json_object_get(js, g_quark_from_string("token_type"));
    if(elem) g_print("found value=%s\n", elem->value.s);
    json_free(js);

    return 0;
}


#endif // TEST_JSON
