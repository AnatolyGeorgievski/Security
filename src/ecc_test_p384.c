#include "ecc.h"
#include <inttypes.h>

enum {
HASH_SHA_1,
HASH_SHA_224,
HASH_SHA_256,
HASH_SHA_384,
HASH_SHA_512,
HASH_SHA_512_224,
HASH_SHA_512_256,
HASH_GOST_TEST,
HASH_GOST_CRYPTO_PRO,
};
extern int ecc_nist_signature_verify2(char * Q, char* RS, uint8_t* msg, int msg_len, int curve_id, int hash_id);

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void hex2bin (uint8_t* buf, const char* s)
{
    uint8_t c1,c2;
    while(s[0]!='\0') {
        if ('0' <= s[0] && s[0]<='9') c1= (s[0] - '0');
        else
        if ('A' <= s[0] && s[0]<='F') c1= (s[0] - 'A' + 10);
        else
        if ('a' <= s[0] && s[0]<='f') c1= (s[0] - 'a' + 10);
        else c1 = 0;
        s++;
        if (s[0]=='\0') break;
        if ('0' <= s[0] && s[0]<='9') c2= (s[0] - '0');
        else
        if ('A' <= s[0] && s[0]<='F') c2= (s[0] - 'A' + 10);
        else
        if ('a' <= s[0] && s[0]<='f') c2= (s[0] - 'a' + 10);
        else c2 = 0;
        /// \todo иначе пропускаем символ, например пропускаем пробелы и переносы строк
        *buf++ = c1<<4 | c2;
        s++;
    }
}


int ecc_test_p384()
{
char* Msg[10],*Q[10],*RS[10];
int SHA[10];
Msg[0]= "3f0783a58e66f3d2c0ccfb5fac3f09db6f8609d0592bc77fdffed9cf0e137d26a867057665f3ad81beebbbdb723d5a47c580828f10f7347ab8a9c24d195f736dfae6eae37d88fe3b4735e7c669a80ac1913e5c24c8c1d5cdb15f994f3ec2f1c774752e14f596b38c2fbf037616d608244d3da7d4badf351330f947e04cc350e7";
Q[0]  = "0874a2e0b8ff448f0e54321e27f4f1e64d064cdeb7d26f458c32e930120f4e57dc85c2693f977eed4a8ecc8db981b4d9"
        "1f69446df4f4c6f5de19003f45f891d0ebcd2fffdb5c81c040e8d6994c43c7feedb98a4a31edfb35e89a30013c3b9267";
RS[0] = "8d9d3e3d0b2b2871ea2f03f27ba8699f214be8d875c0d770b0fff1c4ce341f0c834ac11f9ec12bfdb8320b1724c8c220"
        "62150dfba8e65c0c7be7ef81c87241d2c37a83c27eb31ccc2b3c3957670a744c81be6d741340b5189cc0c547df81b0d2";
SHA[0]= HASH_SHA_1;
Msg[1] ="66ae60b818e65b19c0efab7223a38dd7b8ed1888494bb01dee42d0f0c913ff9f2e16e146a5533956e28af9e8c46faaa0041cc74469e639257b971ddfb17100ab78363439ff2b3883bd17d54adb48a58b75202b4cd5aa82493417bf230436b65cfc3ac64a8e1e874b7b64ca68bcac1cf30e6f363fb2f736502d3e41940ae248af";
Q[1]  = "b4b92211edbd41c5468d2ba70810bc37b5e7c954c7bd0db80c4fa89ccba10bf07cdab953828a068bc0104d28e4040c14"
        "93ed318efce3dff98fc782b788d78658ea5ecde4f716e2d5d0ec2d87a2e761daa1f1658cfb857762caa567baaccf9924";
RS[1] = "aa3978eabd196ddf9cab2815cc9cbab0b61cd639deaf70e093a10a58ddf9f410ee1ab965ff8fbb98efbe812421a613d3"
        "02761a2947e1855806b8a25b9ebb0762be9f5517461a371e5783f34b184f32c4ea684b362119b1a2d8a3ff439f10291f";
SHA[1]= HASH_SHA_1;
Msg[2] ="5ad75a561dfbf320a9c0ea8d51caa9268aa855020f16c2f99dd46e42142a5a3b930f5f7a7f76ac9aca5bf659bddf096c94ab3b2a43dad7f97e12803bba79a396a1782e3b72891ecb18d3e37caed5481d3f8ee32af62a3d3ac8a50ccf855b398fcc7930d1ec201494f5357254aa4de5f27de6261ed0c45e255c420ebc3c7cd4f5";
Q[2] =  "b4ab83a4ded7d76aa15eaecb1bafe59427d3cfc38564af9123cb707da2405184acd40a6c093ba29e321ba0f67c1e0c6a"
        "26e2902499495f8550e798617a44ac9990c4c1cc3527dc0dd003a15aee3cbd3955151f7863de1692a94aafd3730e7665";
RS[2] = "61e48d5a100049578e820768ea57f30f27ffd1a1f839fabc55e8f4816c9b95d042619cd3bcc7180fd99834e344f53e7f"
        "977b81d43216f31d8bedc3ffe873047817de3441df8b80a321aa0a80931f25a15c6628f43cf8e48d5c6aeca7626b0a18";
SHA[2]= HASH_SHA_224;
Msg[3] = "8291e5acf7a86f9003c1c8e962efc862a69445ce76f65ba6f861900c7b69b2d711715cfb6cac0f757d3bd5d7af2cbfd7f0283f21f43f12c54af4234a1f28e3a326d14465e991f5e5a4e9fe80aea34324024ce34becf4e9ca56cf5fb66601ca53e20fdfdf353d5356be4c9919f0f7eeb0783d8c7c5d86e85ff39e42f016fa9313";
Q[3] = "6f8f2fc40d1db28309c8850bf94d77c01c5449b4fc556e6bf50e5ee805209c4489d8ff9bd781699eb0e42f6a962d56fe"
        "a4c7c77271dbbe7e00d1c6e4287dddc5463c6803a577a18f89a5eea01c6addc12404353abbc128cb9cf2496732312d65";
RS[3] = "327c4642019a635d80dab82f7dc22e3102a3c1ba684c2b6de67d3d3009a17d39ae3d58ca2caec9f6f03f5ba3b406178c"
        "6b1af807cc7265cc6d3049959cd7779ae0de819036647f9510b0e9f7e4c0e3fece5fc3741b68881145a2c944dc5c54d1";
SHA[3]= HASH_SHA_224;
Msg[4] ="862cf14c65ff85f4fdd8a39302056355c89c6ea1789c056262b077dab33abbfda0070fce188c6330de84dfc512744e9fa0f7b03ce0c14858db1952750d7bbe6bd9c8726c0eae61e6cf2877c655b1f0e0ce825430a9796e7420e5c174eab7a50459e291510bc515141738900d390217c5a522e4bde547e57287d8139dc916504e";
Q[4] =  "86ac12dd0a7fe5b81fdae86b12435d316ef9392a3f50b307ab65d9c6079dd0d2d819dc09e22861459c2ed99fbab66fae"
        "ac8444077aaed6d6ccacbe67a4caacee0b5a094a3575ca12ea4b4774c030fe1c870c9249023f5dc4d9ad6e333668cc38";
RS[4] = "798065f1d1cbd3a1897794f4a025ed47565df773843f4fa74c85fe4d30e3a394783ec5723b530fc5f57906f946ce15e8"
        "b57166044c57c7d9582066805b5885abc06e0bfc02433850c2b74973205ca357a2da94a65172086f5a1580baa697400b";
SHA[4]= HASH_SHA_256;
Msg[5] ="69de70edec5001b0f69ee0b0f1dab6fb22a930dee9a12373fe671f9a5c6804ee1cd027872867c9a4e0bdfed523eb14600cfed64fca415188d56eb651d31731cd3e0efec7251c7defde922cf435ba41454a58d2abf5f29ce5b418a836cab1671d8cdc60aa239a17a42072137cfdc0628715c06b19a2ea2e55005701c220c0924f";
Q[5] =  "9a74ea00203c571bd91ae873ce0ed517f8f0a929c1854d68abd3b83a5051c0b686bb37d12958a54940cfa2de23902da7"
        "6f20ccf8fa360a9ec03d7bb79ff17ad885f714757ef62995f824908561dc0c3dffc49d873627936a2fff018b82879ced";
RS[5] = "acc1fcac98c593fb0a0765fce35a601c2e9570d63ea1e612fff8bc99ac2d4d877750bb44cfb1014e52e00b9235e350af"
        "7f53de3afa4146b1447e829ebac8f5645e948cc99e871c07280cc631613cfdaf52ccaeccbe93588a3fd12170a7ec79fa";
SHA[5]= HASH_SHA_256;

Msg[6] ="9dd789ea25c04745d57a381f22de01fb0abd3c72dbdefd44e43213c189583eef85ba662044da3de2dd8670e6325154480155bbeebb702c75781ac32e13941860cb576fe37a05b757da5b5b418f6dd7c30b042e40f4395a342ae4dce05634c33625e2bc524345481f7e253d9551266823771b251705b4a85166022a37ac28f1bd";
Q[6] =  "cb908b1fd516a57b8ee1e14383579b33cb154fece20c5035e2b3765195d1951d75bd78fb23e00fef37d7d064fd9af144"
        "cd99c46b5857401ddcff2cf7cf822121faf1cbad9a011bed8c551f6f59b2c360f79bfbe32adbcaa09583bdfdf7c374bb";
RS[6] = "33f64fb65cd6a8918523f23aea0bbcf56bba1daca7aff817c8791dc92428d605ac629de2e847d43cee55ba9e4a0e83ba"
        "4428bb478a43ac73ecd6de51ddf7c28ff3c2441625a081714337dd44fea8011bae71959a10947b6ea33f77e128d3c6ae";
SHA[6]= HASH_SHA_384;

Msg[7] ="93e7e75cfaf3fa4e71df80f7f8c0ef6672a630d2dbeba1d61349acbaaa476f5f0e34dccbd85b9a815d908203313a22fe3e919504cb222d623ad95662ea4a90099742c048341fe3a7a51110d30ad3a48a777c6347ea8b71749316e0dd1902facb304a76324b71f3882e6e70319e13fc2bb9f3f5dbb9bd2cc7265f52dfc0a3bb91";
Q[7]  = "a370cdbef95d1df5bf68ec487122514a107db87df3f8852068fd4694abcadb9b14302c72491a76a64442fc07bd99f02c"
        "d397c25dc1a5781573d039f2520cf329bf65120fdbe964b6b80101160e533d5570e62125b9f3276c49244b8d0f3e44ec";
RS[7] = "c6c7bb516cc3f37a304328d136b2f44bb89d3dac78f1f5bcd36b412a8b4d879f6cdb75175292c696b58bfa9c91fe6391"
        "6b711425e1b14f7224cd4b96717a84d65a60ec9951a30152ea1dd3b6ea66a0088d1fd3e9a1ef069804b7d969148c37a0";
SHA[7]= HASH_SHA_384;
Msg[8] ="d497dfe02aa5e4fa13178dc1ebda8807f9ef1656c1abc448619f2e22a809d05551526a0e9706febd9e0f7ec9b791bdabc5989cb1957377110cc53006bece1a025c5bc7e9e64eb1517a6fbfff058e0ae85d67adee20fe536caaaa9928bf7afc52fe8cc662037dcafcdae4e57630b0c15aa1552372b5bf22f500cacfdaf52e7b89";
Q[8] =  "c665feccf51e6bca31593087df60f65b9fe14a12022814615deb892eedb99d86069a82aa91319310b66588185282dad6"
        "1e6e25bb8ae7714415b94f89def0f75dcb81d4af6b78d61f277b74b990c11aff51bd12fc88d691c99f2afde7fbd13e51";
RS[8] = "0e18c4063137468fe864fdc405ad4e120176eb91b4538b28ce43a22ae1a310cc22a2f7a2b3a0f3d15e0f82038b4a4301"
        "5a1620e42041ce4357daf824befbb2ed65596bcd8214e88726149b26b1f416b9472a8877413f1c3705fc2edf4731943b";
SHA[8]= HASH_SHA_512;
Msg[9] ="2fc5392afee78db70368ab391d7d765ea656f13b1f71e5f7550d77443d1091b0df7efc9f4e4fd568827040e3fa7a4b07b6f8eaacaa640711c7d65b04122f7dfc4deba77736382e47a36dda3f379cdde3773a2c7f101825988f13a6b6b64259615c5b6897ba2866d0a0924b4626a0e8db1a97696dd506273a2fb0914283b3d8af";
Q[9] =  "83a4fecc0bf0a353b0acf6f54094b822f2b12564e172b296f3461cafa7315d7d31d0089b1b4c18ad3c86bd18f539774a"
        "e4fd57c5b2937e6fba1e7d72fc3f02352bd79c13611931935f4dfd073b9379f862f2277585137e996e212b5b6533dcba";
RS[9] = "fb02804010a570d702ebfbcf3d6cc9d55ddac2bd4b4de56d325e9790571b1737f91d3fa1d4caeec6eea806195aed3187"
        "1fd20fe383e907e77639c05594642798619b2742090919bedeefb672c5700881baf0df19b9529d64bc7bb02683226103";
SHA[9]= HASH_SHA_512;
        int res = 0;
#if 0
        int curve_id = EC_NIST_P384;
        int i;
        printf("\nNIST P-384, SHA signature verify test\n");
        for(i=0;i<8;i++){
//            if (i==0 || SHA[i]!=SHA[i-1])
//                printf("\n %s, %s signature verify test", ecc_domain_params[curve_id].name, ecc_hashes[SHA[i]].name);
             int msg_len = strlen(Msg[i]);
    //        printf("\nlength=%d", msg_len);
            uint8_t *msg = malloc(msg_len);
            hex2bin(msg, Msg[i]);

            res += ecc_nist_signature_verify2(Q[i], RS[i], msg, msg_len>>1, curve_id, SHA[i]);

            free(msg);
        }
#endif // 0
//        if (res!=0)
        return res;
}
