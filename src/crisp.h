#ifndef CRISP_H
#define CRISP_H
#include <stdint.h>

#define CRISP_NULL_NULL 	0 // не используется
#define MAGMA_CTR_CMAC 		1
#define MAGMA_NULL_CMAC 	2
#define MAGMA_CTR_CMAC8 	3
#define MAGMA_NULL_CMAC8 	4

#define CRISP_WINDOW 32
typedef struct _crisp_ctx CRISP_t;
struct _crisp_ctx {
//    uint16_t version;
	uint8_t CS;		//!< режим шифрования 01: MAGMA-CTR-CMAC 02: MAGMA-NULL-CMAC 03: MAGMA-CTR-CMAC8
	uint8_t klen;	//!< Длина поля идентификатора ключа (KeyId)
	uint8_t hlen; 	//!< Длина заголовка
	uint8_t slen; 	//!< длина поля SourceIdentifier

	uint8_t *KeyId;	//!< идентификатор ключа
	uint64_t seq_max; //!< Содержит идентификатор последнего сообщения
	uint64_t seq_min; //!< Начальное значение окна
	
	uint32_t *K;		//!< Базовый ключ
	uint8_t *SourceIdentifier;
	uint32_t recvd[CRISP_WINDOW/32];// пометки детектирования пакетов

	void* hdl;		 //!< контекст транспортного протокола (MQTT)
	uint8_t* buffer; //!< буфер для формирования пакетов MTU 2048 байт
};
// выделение буфера под запись данных
uint8_t* crisp_alloc(CRISP_t* ctx);
// кодирование декодирование
int crisp_encode(CRISP_t* ctx, uint8_t* data, int dlen);
int crisp_decode(CRISP_t* ctx, uint8_t* data, int dlen);

// Формат прикладного сообщения
struct _ProtoQa_header {
	uint8_t Ver;
	uint8_t SenderID[16];
	uint8_t RecipientID[16];
	uint8_t SessionID[4];
	uint8_t MsgType;
};

enum _MsgType {
//!< 00 Ответ c кодом отчета
//!< 01 Запрос согласования параметров
//!< 02 Ответ на запрос согласования параметров
//!< 03 Запрос на получение нового ключа
//!< 04 Запрос на получение ранее запрошенного ключа
//!< 05 Запрос на получение нового или ранее запрошенного ключа
//!< 06 Ответ на запрос получения ключа
//!< 07 Запрос на получение случайного числа
//!< 08 Ответ на запрос получения случайного числа
//!< 09 Запрос передачи произвольных данных
//!< 0A Запрос передачи информационного сообщения
// Свободные значения могут использоваться производителями по своему усмотрению.
MsgType_MAX = 0x0A
};

// фильтр сообщения
struct _filter {
	char* topic;
	uint16_t length:11;
	uint16_t QoS:2;
};
#endif//CRISP_H
