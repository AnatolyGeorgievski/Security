/*!
 */
#include "sign.h"
#include <glib.h>

//extern const Sign __start__SignSchemes[];
//extern const Sign __stop__SignSchemes[];
static GSList* sign_alg_list = NULL;
void sign_register(const Sign* sign)
{
    sign_alg_list = g_slist_append(sign_alg_list, (void*)sign);
}
#if 0
void __attribute__((constructor)) sign_init()
{
    const Sign *sign = SEGMENT_START(SignSchemes);
    const Sign *sign_top = SEGMENT_STOP(SignSchemes);
    while (sign < sign_top)
    {
        printf("SIGN_ALG: %s\n", sign->name);
        sign++; //i++;
    }
}
#endif // 0
static void __attribute__((destructor)) sign_fini()
{
    g_slist_free(sign_alg_list); sign_alg_list=NULL;
}
/*! \brief выбор хеш-функции по идентификатору

    \param alg_id уточениение по поводу параметров - список параметров
 */
const Sign* sign_select(int sign_id, int alg_id)
{
    GSList * list = sign_alg_list;
    while (list){
        const Sign* sign = list->data;
        if (sign->id == sign_id) {
            return sign;
        }
        list = list->next;
    }
#if 0
    const Sign *sign = SEGMENT_START(SignSchemes);
    const Sign *sign_top = SEGMENT_STOP(SignSchemes);
    while (sign < sign_top)
    {
        if (sign->id == sign_id) {
            //printf("SIGN_ALG: signature algorithm %s\n", sign->name);
            return sign;
        }
        sign++; //i++;
    }
    printf("SIGN_ALG-ERR: signature algorithm not found\n");
#endif // 0
    return (void*)0;
}
