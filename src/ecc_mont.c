/*! \brief умножение Монтгомери
    \file ecc_mont.c

	Изоморфизм между кривыми Монтгомери и скрученными кривыми Эдвардса
E: eu^2+y^2 = 1+du^2v^2
M: By^2 = x^3+Ax^2 +x, где A=2(e+d)/(e-d)=3t/s, B=4/(e-d)=1/s

	Трансформация кривой Монтгомери в форму Эдвардса
E: ex^2+y^2=1+dx^2y^2
M: Bv^2 = u^3+Au^2+u, где B = 4/(e-d), A=2(e+d)/(e-d)  ; e = (A+2)/B, d = (A-2)/B
u=(1+y)/(1-y), v=u/x  => x=u/v, y=(u-1)/(u+1)

The correct code for converting to Montgomery format is this (note the inversion, needed
to ensure that z1 == 1, which allows a faster Montgomery ladder):

// sqrt(-486664), in 26/25 bit limbs.
fe K = { 54885894, 25242303, 55597453,  9067496, 51808079,
         33312638, 25456129, 14121551, 54921728,  3972023 };

// Actual conversion
fe x1, y1, z1, x2, z2, x3, z3, t1, t2, t3, t4;
fe_sub(z1, q->Z, q->Y);  fe_mul(z1, z1, q->X);  fe_invert(z1, z1);
fe_add(t1, q->Z, q->Y);
fe_mul(x1, q->X, t1  );  fe_mul(x1, x1, z1);
fe_mul(y1, q->Z, t1  );  fe_mul(y1, y1, z1);
fe_mul(y1, K, y1);  // missing multiplication
fe_1(z1);

(Even though we use projective coordinates, the Montgomery ladder is faster when it can assume z1 is equal to one. This compensates the cost of the inversion.)

The correct code for converting back to Twisted Edwards format is this:

fe_sub(t1  , x1, z1);
fe_add(t2  , x1, z1);
fe_mul(x1  , K , x1);  // missing multiplication
fe_mul(p->X, x1, t2);
fe_mul(p->Y, y1, t1);
fe_mul(p->Z, y1, t2);
fe_mul(p->T, x1, t1);


 */
#include "ecc.h"
#include "sign.h"
static void ec_point_mont_cpy(ECC_PointM* Q, BNuint* px, MPCtx *ctx)
{
    int size = ctx->size;
    bn_move (Q->x, px, size);
    bn_set_1(Q->z, size);
}
/*! \brief преобразование в форму Монтгомери */
void ec_point_ed2mont(ECC_PointM* Q, BNuint* qx, BNuint* qy, BNuint* s, BNuint* t, MPCtx* ctx)
{
	mp_subm(ctx, Q->x, qx, t);
	mp_addm(ctx, Q->z, Q->x, s);
	mp_mulm(ctx, Q->x, Q->x, Q->z);
	mp_mulm(ctx, Q->y, Q->y, qy);
	mp_mulm(ctx, Q->z, Q->z, qy);
}

/*!
Algorithm 1: xADD: differential addition on P1
Input: (XP , ZP ), (XQ, ZQ), and (X_), Z_) in F2 q such that (XP : ZP ) = x(P),
(XQ : ZQ) = x(Q), and (X_ : Z_) = x(P - Q) for P and Q in E(Fq)
Output: (X⊕, Z⊕) in F2 q such that (X⊕ : Z⊕) = x(P ⊕ Q) if P ⊖ Q / ∈ {O, T },
otherwise X⊕ = Z⊕ = 0
Cost: 4M + 2S + 3a + 3s, or 3M + 2S + 3a + 3s if Z_ is normalized to 1
1 V0 ← XP + ZP // 1a
2 V1 ← XQ − ZQ // 1s
3 V1 ← V1 · V0 // 1M
4 V0 ← XP − ZP // 1s
5 V2 ← XQ + ZQ // 1a
6 V2 ← V2 · V0 // 1M
7 V0 ← V1 + V2 // 1a
8 V0 ← V0^2 // 1S
9 V1 ← V1 − V2 // 1s
10 V1 ← V1^2 // 1S
11 X⊕ ← Z_ · V0 // 1M / 0M if Z_ = 1
12 Z⊕ ← X_ · V1 // 1M
13 return (X⊕ : Z⊕)
*/
static void ec_point_mont_add(ECC_PointM* Q, ECC_PointM* P, BNuint* G_x, MPCtx *ctx)
{
    BNuint A[ctx->asize] BN_ALIGN;
    BNuint B[ctx->asize] BN_ALIGN;
    BNuint C[ctx->asize] BN_ALIGN;

    mp_addm(ctx, A, P->x, P->z);
    mp_subm(ctx, B, Q->x, Q->z);
    mp_mulm(ctx, B, B, A);
    mp_mulm(ctx, B, B, A);
    mp_subm(ctx, A, P->x, P->z);
    mp_addm(ctx, C, Q->x, Q->z);
    mp_mulm(ctx, C, C, A);
    mp_addm(ctx, A, B, C);
    mp_sqrm(ctx, Q->x, A);
    mp_subm(ctx, B, B, C);
    mp_sqrm(ctx, B, B);
    mp_mulm(ctx, Q->z, B, G_x);
}
/*!
Algorithm 2: xDBL: pseudo-doubling on P1 from E(A,B)
Input: (XP , ZP ) in F2 q such that (XP : ZP ) = x(P) for P in E(Fq)
Output: (X[2]P , Z[2]P ) in F2 q such that (X[2]P : Z[2]P ) = x([2]P) if P / ∈ {O, T },
otherwise Z[2]P = 0
Cost: 2M + 2S + 1c + 3a + 1s
1 V1 ← XP + ZP  // 1a
2 V1 ← V1^2     // 1S
3 V2 ← XP − ZP  // 1s
4 V2 ← V2^2     // 1S
5 X_2P ← V1 · V2 // 1M
6 V1 ← V1 − V2  // 1s
7 V3 ← ((A + 2)/4) · V1 // 1c
8 V3 ← V3 + V2  // 1a
9 Z_2P ← V1 · V3 // 1M
10 return (X_2P : Z_2P )
*/
static void ec_point_mont_dup(ECC_PointM* Q, BNuint* s, MPCtx *ctx)
{
    BNuint A[ctx->asize] BN_ALIGN;
    BNuint B[ctx->asize] BN_ALIGN;
    BNuint C[ctx->asize] BN_ALIGN;

    mp_addm(ctx, A, Q->x, Q->z);
    mp_subm(ctx, B, Q->x, Q->z);
    mp_sqrm(ctx, A, A);
    mp_sqrm(ctx, B, B);
    mp_mulm(ctx, Q->x, A, B);
    mp_subm(ctx, A, A, B);
    mp_mulm(ctx, C, A, s);
    mp_addm(ctx, C, C, B);
    mp_mulm(ctx, Q->z, A, C);
}
/*! \brief Умножает точку на эллиптической кривой на число P = kG
    Используется метод Монтгомери "ladder"
    \param P точка на эллиптической кривой задана в аффинных координатах (x,y,1)
 */
void ec_point_mont_mul_ladder(ECC_PointM *P, BNuint *G_x, BNuint * k, BNuint* sc, MPCtx* ctx)
{
    BNuint v[2][ctx->asize] BN_ALIGN;
    ECC_PointM Q = {v[0],v[1]};
    int i=ctx->size;
    while (i>0 && k[i-1]==0) i--;
    i=(i<<BN_BIT_LOG)-1;
    while (i>=0 && !bn_bit_test(k, i)) i--;

    ec_point_mont_cpy( P, G_x, ctx);
    ec_point_mont_cpy(&Q, G_x, ctx);
    ec_point_mont_dup(&Q, sc, ctx);

    register ECC_PointM *p=P,*q=&Q;
    for (i--; i>= 0; i--){
        if (bn_bit_test(k, i)) {// todo swap (q,p)
            q = &Q, p =  P;
        } else {
            q =  P, p = &Q;
        }
        ec_point_mont_add(q, p, G_x, ctx);
        ec_point_mont_dup(p, sc, ctx);
    }
}
