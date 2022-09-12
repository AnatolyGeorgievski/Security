/*! \brief Алгоритмы выработки ключей
    \file ecc_dh.c

    Р 1323565.1.030—2020
	\see [RFC5869] Extract-and-Expand HKDF, May 2010
	https://datatracker.ietf.org/doc/html/rfc5869
 */
/*! \brief Алгоритм выработки сессионного ключа на основе октрыго ключа */
ECDH( *x, *y,  d, Q)
{
}
/*! 8.3 Обновление секретных значений */
/*! \brief 8.5 Выработка общего секретного значения ECDHE */
ECDHE( *x, h, d, P)
{
    mp_mulm(ctx, k, h, d);
    ec_point_mulP_x(x, k, P, ctx);
}
vko
/*!
KDF_GOSTR3411_2012_256, описанным в Р 50.1.113-2016:
Divers1 (К, D) = KDF256 (К, "level1", D);
Divers2 (К, D) = KDF256 (К, "level2", D);
Divers3 (К, D) = KDF256 (К, "level3", D)
*/
KDF256();
// Р 1323565.1.030—2020 8.1.1 Функция HKDF-Extract
HKDF_Extract (md, salt, ikm){
    hmac(md, prk, salt, ikm);
}
//! \brief 8.1.2 Функция HKDF-Expand
HKDF_Expand(PRK, info, L)
//! \brief 8.1.3 Функция HKDF-Expand-Label
HKDF_Expand_Label(Secret, Label, Context, Length)
//! \brief 8.1.4 Функция Derive-Secret
Derive_Secret (Secret, Label, Messages)

TLSTREE()
// 8.6 Выработка предварительно распределенного секрета PSK
iPSK = HKDF_Expand_Label(RMS, "resumption", ticket_nonce, HLen)


