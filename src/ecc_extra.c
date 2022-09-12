/*! \brief Все что не входит в рабочуюю версию скопировано сюда

-- Опреации в чудновских координатах

*/
#include "ecc.h"
#include "sign.h"



void ec_point_add_aac(ECC_PointCh *Q, BNuint* qx, BNuint* qy, BNuint* px, BNuint* py, MPCtx * ctx)//BNuint *prime, int size)
{
    BNuint A[ctx->asize] BN_ALIGN;
    BNuint B[ctx->asize] BN_ALIGN;

    mp_subm (ctx, Q->z, px, qx);      // E = X2 - X1
    mp_sqrm (ctx, Q->z2, Q->z);      // G =(X2 - X1)^2

    mp_subm (ctx, Q->y, py, qy);      // F = Y2 - Y1

    mp_addm (ctx, B, qx, px);
    mp_mulm (ctx, B, B, Q->z2);
    mp_sqrm (ctx, A, Q->y);           // X_3 = F^2-(X1+X2)*G
    mp_subm (ctx, Q->x, A, B);

    mp_subm (ctx, A, qx, Q->x);      // Y_3 = F(x1-X_3)-Y_1*H
    mp_mulm (ctx, A, A, Q->y);
    mp_mulm (ctx, B, Q->z, qy);
    mp_subm (ctx, Q->y, A, B);
}


#if 0
void ec_point_add_a2j_x(BNuint* qx, ECC_Point *Q, ECC_Point* P, MPCtx * ctx)
{
    if (mp_is_zero(ctx, &Q->z)){
        ec_point_copy_a2j(Q, P, ctx);
        return;
    }
    A, E, H;

    mp_sqrm (ctx, &A, &Q->z);       // A = Z1^2
    mp_mulm (ctx, &E, &A, &P->x);   // E = X2*Z1^2
    mp_subm (ctx, &E, &E, &Q->x);   // E = X2*Z1^2 - X1

    mp_mulm (ctx, &A, &A, &Q->z);   // A = Z1^3;
    mp_mulm (ctx, &A, &A, &P->y);   // A = Y2*Z1^3
    mp_subm (ctx, &A, &A, &Q->y);   // A = Y2*Z1^3 - Y1

    mp_sqrm (ctx, qx, &E);          // x = (X2*Z1^2 - X1)^2
    mp_mulm (ctx, &H, qx, &E);      // H = (X2*Z1^2 - X1)^3
    mp_mulm (ctx, qx, qx, &Q->x);   // x = (X2*Z1^2 - X1)^2*X1

    mp_sqrm (ctx, &A, &A);          // A = (Y2*Z1^3 - Y1)^2
    mp_dubm (ctx, qx, qx);
    mp_addm (ctx, qx, qx, &H);
    mp_subm (ctx, qx, &A, qx);

    mp_mulm (ctx, &A, &E, &Q->z); // Z_3 = Z_1*E
    mp_invm (ctx, &A, &A);
    mp_sqrm (ctx, &A, &A);
    mp_mulm (ctx, qx, qx, &A);
}
#endif
/*! \brief Умножает точку на эллиптической кривой на число Q = kP
    Используется метод Right-to-Left \see Alg 3.26
    \param P точка на эллиптической кривой задана в аффинных координатах (x,y,1)
 */
void ec_point_mul_26(ECC_Point *Q, ECC_Point *P0, BNuint * k, BNuint* a, MPCtx* ctx)
{
    ec_point_copy_j2j (P, P0, ctx);
    if (k[0]&1)
        ec_point_copy (Q, P0, ctx);
    else
        ec_point_infty(Q, ctx);

    int i;
    for (i=1; i<(ctx->size<<5); i++){
        ec_point_dup(P, a, ctx);
        if (bn_bit_test(k, i))
            ec_point_add(Q,P, ctx);
    }
}
/*! \brief Умножает точку на эллиптической кривой на число Q = kP
    Используется метод Left-to-Right \see Alg 3.27
    \param P точка на эллиптической кривой задана в аффинных координатах (x,y,1)
 */
void ec_point_mul_27(ECC_Point *Q, ECC_Point *P, BNuint * k, BNuint* a, MPCtx* ctx)
{
    int i=ctx->size;
    while (i>0 && k[i-1]==0) i--;
    i=(i<<BN_BIT_LOG)-1;
    while (i>=0 && !bn_bit_test(k, i)) i--;
    if (i<0) {
        ec_point_infty(Q, ctx);
    } else {
        ec_point_copy_a2j(Q, P->x, P->y, ctx);
        i--;
        for (; i>= 0; i--){
            ec_point_dup(Q, a, ctx);
            if (bn_bit_test(k, i))
                ec_point_add_a2j(Q,P->x, P->y, ctx);
        }
    }
}
/*! тоже в чудновских координатах
использован для тестирования алгоритма
 */
void ec_point_mul_c2c(ECC_Point *Q, ECC_Point *P, BNuint * k, BNuint* a, MPCtx* ctx)
{
    ECC_PointCh P1;
    ec_point_ch_init (&P1, ctx);
    ec_point_copy_a2c(&P1, P, ctx);
    ECC_PointCh Q1;
    ec_point_ch_init (&Q1, ctx);
    ec_point_ch_infty(&Q1, ctx);
    int i;
    for (i=(ctx->size<<5)-1; i>= 0; i--){
        ec_point_ch_dup(&Q1, a, ctx);
        if (bn_bit_val(k, i)){
            ec_point_add_c2c(&Q1,&P1, ctx);
//            ec_point_ch_add_mixed(&Q1,P->x, P->y, ctx);
        }
    }
    ec_point_copy_c2j(Q, &Q1, ctx);
    ec_point_ch_free(&Q1, ctx);
    ec_point_ch_free(&P1, ctx);
}
/*! \brief тестовый метод умножения со сложенем
 */
void ec_point_mul_c2j(ECC_Point *Q, ECC_Point *P, BNuint * k, BNuint* a, MPCtx* ctx)
{
    ECC_PointCh P1;
    ec_point_ch_init (&P1, ctx);
    ec_point_copy_a2c(&P1, P, ctx);
    ec_point_infty(Q, ctx);
    int i;
    for (i=(ctx->size<<5)-1; i>= 0; i--){
        ec_point_dup(Q, a, ctx);
        if (bn_bit_val(k, i)){
            ec_point_add_c2j(Q,&P1, ctx);
        }
    }
    ec_point_ch_free(&P1, ctx);
}
/*! \brief Умножает точку на эллиптической кривой на скаляр Q = kP
    Используется метод Left-to-Right типа Binary NAF \see Alg 3.31
    сложение производится только в начале или в конце последовательности единиц
    \param P точка на эллиптической кривой задана в аффинных координатах (x,y,1)
 */
void ec_point_mul(ECC_Point *Q, ECC_Point *P, BNuint * k, BNuint* a, MPCtx* ctx)
{
    int sign=0;
    BNuint pn[ctx->asize] BN_ALIGN;
    bn_sub(pn, ctx->prime, P->y, ctx->size);// -P = (x,-y)
    int i = (ctx->size<<BN_BIT_LOG);
    uint32_t kk = bn_bit_val(k, i-1)<<1 | bn_bit_val(k, i-2);
    if ((kk)==3){
        ec_point_copy_a2j (Q, P->x, P->y, ctx);
        sign = 1;
    } else {
        ec_point_infty(Q, ctx);
    }
    do {
        ec_point_dup(Q, a, ctx);
        kk<<=1;
        if (i>=3) kk |= bn_bit_val(k, i-3);
        if ((kk&7)==3){
            ec_point_add_a2j(Q,P->x, P->y, ctx);
            sign = 1;
        } else
        if ((kk&6)==4){
            if (sign){
                ec_point_add_a2j(Q,P->x, pn, ctx);
                sign = 0;
            } else {
                ec_point_add_a2j(Q,P->x, P->y, ctx);
            }
        }
    } while (--i);
    //mp_free1(ctx, &n);
}

/*! сложение в смещанных координатах Чудновский - аффинные */
void ec_point_ch_add_mixed(ECC_PointCh *Q, BNuint* px, BNuint* py, MPCtx * ctx)//BNuint *prime, int size)
{
    if (bn_is_zero(Q->z, ctx->size)){
        bn_move(Q->x, px, ctx->size);
        bn_move(Q->y, py, ctx->size);
        bn_set_1(Q->z,  ctx->size);
        bn_set_1(Q->z2, ctx->size);
        bn_set_1(Q->z3, ctx->size);
        return;
    }
    BNuint A[ctx->asize] BN_ALIGN;
    BNuint B[ctx->asize] BN_ALIGN;
    BNuint C[ctx->asize] BN_ALIGN;
    BNuint D[ctx->asize] BN_ALIGN;
    BNuint E[ctx->asize] BN_ALIGN;
    BNuint F[ctx->asize] BN_ALIGN;
    BNuint G[ctx->asize] BN_ALIGN;
    BNuint H[ctx->asize] BN_ALIGN;
    BNuint I[ctx->asize] BN_ALIGN;

    mp_mulm (ctx, C, Q->z2, px);    // C = X2*Z1^2
    mp_subm (ctx, E, C, Q->x);      // E = X2*Z1^2 - X1

    mp_mulm (ctx, D, Q->z3, py);    // D = Y2*Z1^3
    mp_subm (ctx, F, D, Q->y);      // F = Y2*Z1^3 - Y1
    mp_sqrm (ctx, G, E);            // G =(X2*Z1^2 - X1)^2
    mp_mulm (ctx, H, G, E);         // H =(X2*Z1^2 - X1)^3
    mp_mulm (ctx, I, G, Q->x);      // I =(X2*Z1^2 - X1)^2*X1

    mp_sqrm (ctx, A, F);            // X_3 = F^2-(H+2I)
    mp_dubm (ctx, B, I);
    mp_addm (ctx, B, B, H);
    mp_subm (ctx, Q->x, A, B);

    mp_subm (ctx, A, I, Q->x);      // Y_3 = F(I-X_3)-Y_1*H
    mp_mulm (ctx, A, A, F);
    mp_mulm (ctx, B, H, Q->y);
    mp_subm (ctx, Q->y, A, B);

    mp_mulm (ctx, Q->z, Q->z, E);   // Z_3 = Z_1*(X2*Z1^2 - X1)
    mp_sqrm (ctx, Q->z2, Q->z);     // Z_3^2
    mp_mulm (ctx, Q->z3, Q->z2, Q->z);   // Z_3^3


}
/*! Сложение в чудновских координатах C+C => C
12 M 4S 6A
 */
void ec_point_add_c2c(ECC_PointCh *Q, ECC_PointCh* P, MPCtx * ctx)
{
    if (bn_is_zero(Q->z, ctx->size)){
        ec_point_copy_c2c(Q,P, ctx);
        return;
    }

    BNuint C[ctx->asize] BN_ALIGN;
    BNuint D[ctx->asize] BN_ALIGN;
    BNuint E[ctx->asize] BN_ALIGN;
    BNuint F[ctx->asize] BN_ALIGN;
    BNuint G[ctx->asize] BN_ALIGN;
    BNuint z[ctx->asize] BN_ALIGN;
    BNuint t[ctx->asize] BN_ALIGN;

    mp_mulm(ctx, C, P->y, Q->z3);    // C = Y2*Z1^3
    mp_mulm(ctx, D, Q->y, P->z3);    // D = Y1*Z2^3
    mp_mulm(ctx, E, P->x, Q->z2);    // E = X2*Z1^2
    mp_mulm(ctx, F, Q->x, P->z2);    // F = X1*Z2^2

    mp_subm(ctx, G, E, F);          // G = E - F =
    mp_addm(ctx, F, F, E);          // F = E + F
    // Z3 = G*Z1*Z2
    mp_mulm(ctx, z, P->z, G);       // z = Z2*G
//if (bn_is_zero(z, ctx->size)) printf("divide 0");
    mp_mulm(ctx, Q->z, z, Q->z); // Z3 = Z1*z = G*Z1*Z2
    mp_sqrm(ctx, Q->z2, Q->z);
    mp_mulm(ctx, Q->z3, Q->z2, Q->z);

    mp_subm(ctx, C, C, D);          // C = C - D
    // X3 = C^2 - G^2(E+F) = (C-D)^2 - G^2(X2*Z1^2 + X1*Z2^2)
    mp_sqrm(ctx, D, C); // D = C^2
    mp_sqrm(ctx, G, G); //  G^2
    mp_mulm(ctx, t, F, G);  // t = G^2*(E+F)
    mp_sqrm(ctx, G, z);     // F = z^2
    mp_mulm(ctx, F, G, Q->x);     // F = X1* z^2
    mp_mulm(ctx, z, z, G);      // z = z^3
    mp_mulm(ctx, z, z, Q->y);   // z = z^3*Y1
    mp_subm(ctx, Q->x, D, t);   // X3
    mp_subm(ctx, F, F, Q->x);     // F = X1* z^2 - X3
    mp_mulm(ctx, F, F, C);      //
    mp_subm(ctx, Q->y, F, z);    // Y3 = C(z^2*X1 - X3) - Y1*z^3
}
/*! Сложение в чудновских координатах J+C => J
    \param Q - точка в якобианских коорднинатах
    \param P - точка в чудновских координатах
12 M 4S 5A
 */
void ec_point_add_c2j(ECC_Point * const Q, const ECC_PointCh* const P, const MPCtx * const ctx)
{
    if (bn_is_zero(Q->z, ctx->size)){
        ec_point_copy_c2j(Q, P, ctx);
        return;
    }

    BNuint C[ctx->asize] BN_ALIGN;
    BNuint D[ctx->asize] BN_ALIGN;
    BNuint E[ctx->asize] BN_ALIGN;
    BNuint F[ctx->asize] BN_ALIGN;
    BNuint G[ctx->asize] BN_ALIGN;
    BNuint z[ctx->asize] BN_ALIGN;
    BNuint t[ctx->asize] BN_ALIGN;

    mp_sqrm(ctx, z, Q->z);      // Z1^2
    mp_mulm(ctx, E, P->x, z);    // E = X2*Z1^2
    mp_mulm(ctx, F, Q->x, P->z2);    // F = X1*Z2^2
    mp_mulm(ctx, z, z, Q->z);    //Z1^3
    mp_mulm(ctx, C, P->y, z);    // C = Y2*Z1^3
    mp_mulm(ctx, D, Q->y, P->z3);    // D = Y1*Z2^3

    mp_subm(ctx, G, E, F);          // G = E - F =
    mp_addm(ctx, F, F, E);          // F = E + F
    // Z3 = G*Z1*Z2
    mp_mulm(ctx, z, P->z, G);       // z = Z2*G
//if (bn_is_zero(z, ctx->size)) printf("divide 0");
    mp_mulm(ctx, Q->z, z, Q->z); // Z3 = Z1*z = G*Z1*Z2

    mp_subm(ctx, C, C, D);          // C = C - D
    // X3 = C^2 - G^2(E+F) = (C-D)^2 - G^2(X2*Z1^2 + X1*Z2^2)
    mp_sqrm(ctx, D, C); // D = C^2
    mp_sqrm(ctx, G, G); //  G^2
    mp_mulm(ctx, t, F, G);  // t = G^2*(E+F)
    mp_sqrm(ctx, G, z);     // F = z^2
    mp_mulm(ctx, F, G, Q->x);     // F = X1* z^2
    mp_mulm(ctx, z, z, G);      // z = z^3
    mp_mulm(ctx, z, z, Q->y);   // z = z^3*Y1
    mp_subm(ctx, Q->x, D, t);   // X3
    mp_subm(ctx, F, F, Q->x);     // F = X1* z^2 - X3
    mp_mulm(ctx, F, F, C);      //
    mp_subm(ctx, Q->y, F, z);    // Y3 = C(z^2*X1 - X3) - Y1*z^3
}
void ec_point_ch_init(ECC_PointCh * P, MPCtx* ctx)
{
    P->x = mp_new(ctx);
    P->y = mp_new(ctx);
    P->z = mp_new(ctx);
    P->z2= mp_new(ctx);
    P->z3= mp_new(ctx);
}
void ec_point_ch_infty(ECC_PointCh* P, MPCtx *ctx)
{
    bn_set_1(P->x, ctx->size);
    bn_set_1(P->y, ctx->size);
    bn_set_0(P->z, ctx->size);
    bn_set_0(P->z2, ctx->size);
    bn_set_0(P->z3, ctx->size);
}
void ec_point_ch_free(ECC_PointCh * P, MPCtx* ctx)
{
    mp_free(ctx, P->z3);
    mp_free(ctx, P->z2);
    mp_free(ctx, P->z);
    mp_free(ctx, P->y);
    mp_free(ctx, P->x);
}
/*! копировать точку из чудновских в якобианские координаты*/
void ec_point_copy_c2j(ECC_Point* Q, const ECC_PointCh* const P, const MPCtx * const ctx)
{
    int size = ctx->size;
    bn_move (Q->x, P->x, size);
    bn_move (Q->y, P->y, size);
    bn_move (Q->z, P->z, size);
}
void ec_point_copy_c2c(ECC_PointCh* Q, const ECC_PointCh* P, MPCtx *ctx)
{
    int size = ctx->size;
    bn_move (Q->x, P->x, size);
    bn_move (Q->y, P->y, size);
    bn_move (Q->z, P->z, size);
    bn_move (Q->z2,P->z2,size);
    bn_move (Q->z3,P->z3,size);
}
/*! копировать точку из аффинных в чудновские координаты*/
void ec_point_copy_a2c(ECC_PointCh* Q, ECC_Point* P, MPCtx *ctx)
{
    int size = ctx->size;
    bn_move (Q->x, P->x, size);
    bn_move (Q->y, P->y, size);
    bn_set_1(Q->z, size);
    bn_set_1(Q->z2, size);
    bn_set_1(Q->z3, size);
}
/*! удваивание в чудновских координатах */
void ec_point_ch_dup(ECC_PointCh* P, BNuint* a, MPCtx *ctx)
{
    if (bn_is_zero(P->y, ctx->size) || bn_is_zero(P->z, ctx->size)) {
        ec_point_ch_infty(P, ctx);
        return;
    }
    BNuint A[ctx->asize] BN_ALIGN;
    BNuint B[ctx->asize] BN_ALIGN;
    BNuint C[ctx->asize] BN_ALIGN;
    BNuint D[ctx->asize] BN_ALIGN;

/*  отдельно можно рассмотреть случай для a = p-3
    тогда D = 3(X + Z^2)(X - Z^2)
    иначе D = 3X^2 + aZ^4
    */
    if (a == (void*)-3){
//        mp_sqrm (ctx, B, P->z);
        mp_addm (ctx, D, P->x, P->z2);  // D = X + Z^2
        mp_subm (ctx, A, P->x, P->z2);  // A = X - Z^2
        mp_mulm (ctx, B, D, A);
        mp_mulm_ui (ctx, D, B, 3);
    } else if (a == (void*)0){
        mp_sqrm (ctx, B, P->x);         // D = 3X^2
        mp_mulm_ui (ctx, D, B, 3);
    } else {
        mp_sqrm (ctx, B, P->x);         // D = 3X^2 + aZ^4
        mp_mulm_ui (ctx, D, B, 3);
        mp_sqrm (ctx, B, P->z2);
//        mp_sqrm (ctx, B, B);
        mp_mulm (ctx, B, B, a);
        mp_addm (ctx, D, D, B);
    }
    mp_dubm (ctx, P->y, P->y);//, 1);   // Y = 2Y

    mp_sqrm (ctx, A, P->y);         // A = 4Y^2
    mp_mulm (ctx, B, A, P->x);     // B = 4X*Y^2
    mp_sqrm (ctx, C, A);            // C = A^2/2 = 8Y^4
    mp_hlvm (ctx, C);

    mp_mulm (ctx, P->z, P->z, P->y);      // Z_3 = 2YZ
    mp_sqrm (ctx, P->z2, P->z);
    mp_mulm (ctx, P->z3, P->z2, P->z);

    mp_dubm (ctx, A, B);
    mp_sqrm (ctx, P->x, D);//X_3 = D^2-2B
    mp_subm (ctx, P->x, P->x, A);

    mp_subm (ctx, B, B, P->x);        //Y_3 = D(B-X_3) - C
    mp_mulm (ctx, B, D, B);
    mp_subm (ctx, P->y, B, C);
}
