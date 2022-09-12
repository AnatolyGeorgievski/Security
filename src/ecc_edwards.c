/*! \brief Дополнение в форме скрученных кривых эдвардса

    \see https://tools.ietf.org/html/draft-ietf-lwig-curve-representations-01
    \see [RFC 8032] EdDSA: Ed25519 and Ed448 January 2017
    Edwards-Curve Digital Signature Algorithm (EdDSA)

Edw:  x^2+ey^2 = 1+dx^2y^2
Мы поменяли местами координаты x,y чтобы симметрия была по оси Х, как в случае
элл. кривых вейерштрасса (в канонической форме)
Группа:
Обратный элемент к P, -P = (x,-y)
Нейтральный элемент группы О: O=(1,0)
P+(-P) = O, P+O = P

Далее смотрю в методические рекомендации (МР.26.2.002-2018). Вижу преобразование из кривых эдвардса в кривые в канонической форме.
\see 4 "Представление в форме скрученных кривых Эдвардса".
Что является инвариантом в случае кривых эдвардса? как выразить e d, если есть a и b? Куда делся нейтральный элемент?
x = X/Z, y=Y/Z проективные координаты в случае Эдвардса.
(X^2+eY^2)Z^2 = Z^4+dX^2Y^2

Представим уравнение в форме:
W: Y^2 = (X− c)(X^2 + cX + a+ c^2), где b= −c(a+ c^2) коэффициенты принадлежат Fp

Решением может быть только с = -3b/2а
Заменой (u,v) = (X-c,Y) получим уравнение в форме Монтгомери:
M: v^2 = u^3 + Au^2 + Gu, A G принадлежит Fq
v^2 = u^3 + 3cu^2 + (a+3c^2)u

	Трансформация кривой Монтгомери в форму Эдвардса
E: ex^2+y^2=1+dx^2y^2
M: Bv^2 = u^3+Au^2+u, где B = 4/(e-d), A=2(e+d)/(e-d)  ; e = (A+2)/B, d = (A-2)/B
u=(1+y)/(1-y), v=u/x  => x=u/v, y=(u-1)/(u+1)

МР.26.2.002-2018:
E: eu^2+v^2=1+du^2v^2
W: y^2=x^3+ax+b
M: Bv^2=u^3+Au^2+u

(x-t, y)<=>(u,v)
(u,v)=(x-t)/y, ((x-t)-s)/((x-t)+s)
(x-t,y) = s(1+v)/(1-v), s(1+v)/(1-v)*1/u
где t=(e+d)/6, s=(e-d)/4, a=s^2-3t^2, b = 2t^3-ts^2
отсюда получаем s^2 = (a+3t^2), A=3t/s, B=1/s , b = 2t^3-t(a+3t^2) = -t(a+t^2)
t - корень уравнения W при котором (t, 0) переходит в точку (0,0) на кривой Монтгомери

x = (-3b/2а,0)

	Изоморфизм между кривыми Монтгомери и скрученными кривыми Эдвардса
E: eu^2+y^2 = 1+du^2v^2
M: By^2 = x^3+Ax^2 +x, где A=2(e+d)/(e-d)=3t/s, B=4/(e-d)=1/s

Алгоритм Монтгомери для вычисления умножения , координата y не высчитывается.
Input: k, P
Output: kP

1: Q[0] = P, Q[1] = 2P
2: for i = k-2 down to 0:
3:     Q[1 - k[i]] = Q[0] + Q[1]
4:     Q[k[i]] = 2Q[k[i]]
5: return Q[0]

1: Q[0] = P, Q[1] = 2P
2: for i = k-2 down to 0:
if (k[i])
    Q[0] = Q[0] + Q[1]
    Q[1] =2Q[1]
else
    Q[1] = Q[1] + Q[0]
    Q[0] =2Q[0]

5: return Q[0]

    \see [RFC 8410]  Algorithm Identifiers for Ed25519, Ed448, X25519, and X448
        for Use in the Internet X.509 Public Key Infrastructure,
            RFC 8410                  Safe Curves for X.509              August 2018
*/
#include "ecc.h"
#include "sign.h"


/*! \brief присваивает бесконечность - нейтральный элемент поля */
static void ec_point_ed_infty_ext(ECC_PointE* P, MPCtx *ctx)
{
    int size = ctx->size;
    bn_set_0(P->x, size);
    bn_set_1(P->y, size);
    bn_set_1(P->z, size);
    bn_set_0(P->t, size);
}
/*! \brief выполняет копирование точки в афинных координатах в расширенные */
static void ec_point_ed_copy_a2e(ECC_PointE *Q, BNuint* px, BNuint* py, MPCtx *ctx)
{
    int size = ctx->size;
    bn_move (Q->x, px, size);
    bn_move (Q->y, py, size);
    bn_set_1(Q->z, size);
    mp_mulm(ctx, Q->t, px, py);
}
/*! \brief Преобразование точки из расширенных координат в афинные координаты */
void ec_point_ed_affine_ext(BNuint *qx, BNuint *qy, ECC_PointE *Q, MPCtx* ctx)
{
    ec_point_ed_affine(qx, qy, (ECC_Point *)Q, ctx);
}
/*! 9M
def point_add(P, Q):
    A, B = (P[1]-P[0]) * (Q[1]-Q[0]) % p, (P[1]+P[0]) * (Q[1]+Q[0]) % p;
    C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] * Q[2] % p;
    E, F, G, H = B-A, D-C, D+C, B+A;
    return (E*F, G*H, F*G, E*H);
def point_add_a2e(P, Q): 8M+8A
    A, B = (P[1]-P[0]) * (Q[1]-Q[0]) % p, (P[1]+P[0]) * (Q[1]+Q[0]) % p;
    C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] % p;
    E, F, G, H = B-A, D-C, D+C, B+A;
    return (E*F, G*H, F*G, E*H);
def point_dup(P): 4M + 4S+3A
    A, B = 0, (P[1]+P[0]) * (P[1]+P[0]) % p;
    C, D = 2 * P[3] * P[3] * d % p, 2 * P[2] * P[2] % p;
    F, G = D-C, D+C;
    return (B*F, G*B, F*G, B*B);

# Curve constant
d = -121665 * modp_inv(121666) % p
# Base point
g_y = 4 * modp_inv(5) % p
g_x = recover_x(g_y, 0)
G = (g_x, g_y, 1, g_x * g_y % p)
 */
static void ec_point_ed_add_e2e(ECC_PointE* Q, ECC_PointE* P, BNuint* e, BNuint* d, MPCtx *ctx)
{
    BNuint A[ctx->asize] BN_ALIGN;
    BNuint E[ctx->asize] BN_ALIGN;
    BNuint F[ctx->asize] BN_ALIGN;

    mp_subm(ctx, E, Q->y, Q->x);
    mp_addm(ctx, Q->y, Q->y, Q->x);

    mp_subm(ctx, F, P->y, P->x);
    mp_addm(ctx, Q->x, P->y, P->x);

    mp_mulm(ctx, A, E, F);
    mp_mulm(ctx, Q->x, Q->y, Q->x);
    mp_mulm(ctx, Q->t, Q->t, P->t);// C=Q->t
    mp_mulm(ctx, Q->t, Q->t, d);// *=2d
    mp_shlm(ctx, Q->t, Q->t, 1);
    if(P->z)
        mp_mulm(ctx, Q->z, Q->z, P->z);// D= Q->z
    mp_shlm(ctx, Q->z, Q->z, 1);
    mp_subm(ctx, E, Q->x, A);
    mp_subm(ctx, F, Q->z, Q->t);
    mp_addm(ctx, Q->z, Q->z, Q->t);// G=Q->z
    mp_addm(ctx, Q->t, Q->x, A);
    mp_mulm(ctx, Q->x, E, F);
    mp_mulm(ctx, Q->y, Q->z, Q->t);
    mp_mulm(ctx, Q->z, Q->z, F);
    mp_mulm(ctx, Q->t, Q->t, E);
}

/*! \brief присваивает бесконечность
    В поле есть нейтральный элемент. Такой что P+O = P и P + (-P) =O (1,0)
    Обратный элемент -(x,y) = (x, -y) при условии замены переменных, поменять местами x и y
*/
static void ec_point_ed_infty(ECC_Point* P, MPCtx *ctx)
{
    int size = ctx->size;
    bn_set_0(P->x, size);
    bn_set_1(P->y, size);
    bn_set_1(P->z, size);
}
/*! \brief выполняет копирование точки в афинных координатах в проекционные */
static void ec_point_ed_copy_a2p(ECC_Point *Q, BNuint* px, BNuint* py, MPCtx *ctx)
{
    int size = ctx->size;
    bn_move (Q->x, px, size);
    bn_move (Q->y, py, size);
    bn_set_1(Q->z, size);
}
/*! \brief сложение точек в поле скрюченной кривой Эдвардса
Mixed addition.
“Mixed addition” refers to the case that Z2 is known to be 1

(X^2+Y^2)Z^2 = c^2(Z^4 + dX^2Y^2)

A = Z1*Z2, B=A^2, C=X1*X2, D =Y1*Y2, E=d*C*D
F = B-E // (Z1Z2)^2 - dX1X2Y1Y2
G = B+E // (Z1Z2)^2 + dX1X2Y1Y2
X3 = A*F ((X1+Y1)(X2+Y2)-C-D)
Y3 = A*G (D-C)
Z3 = c*F*G

(eX^2+Y^2)Z^2 = (Z^4 + dX^2Y^2)
P3 = P1+P2
O=(0,1) -- нулевой элемент,
-P = (-x1,y1)  -- обратная операция
X3 = (x1y2+x2y1)/(1+dx1x2y1y2)
Y3 = (y1y2-ex1x2)/(1-dx1x2y1y2)

2P удвоение
x = (2xy)/(1+dx^2y^2), y=(x^2-ey^2)/(1-dx^2y^2)

Изоморфизм между кривыми в форме Монтгомери
Bv^2 = u^3+Au^2+u, A=2(e+d)/(e-d), B=4/(e-d) e=(A+2)/B d=(A-2)/B

основан на замене координат

u = (1+y)/(1-y), v=u/x => x=u/v, y = (u-1)/(u+1)
Изоморфизм между Эдвардсом и Вейерштрассом (канонической формой)
v^2 = u^3+Au+B


Бессалов поменял местами х, y.
(x1,y1)+(x2,y2) = (x1x2-ey1y2)/(1-dx1x2y1y2), (x1y2+x2y1)/(1+dx1x2y1y2)

Q(X1/Z1, Y1/Z1) + P(X2,Y2)
X3 = Z1Z2(Z1^2*Z2^2 + dX1X2Y1Y2)(X1X2-eY1Y2)
Y3 = Z1Z2(Z1^2*Z2^2 - dX1X2Y1Y2)(X1Y2 +Y1X2)
Z3 = (Z1^2*Z2^2 - dX1X2Y1Y2)(Z1^2*Z2^2 + dX1X2Y1Y2)

Обозначим
A=Z1Z2, B=A^2, C=X1X2, D=Y1Y2, E=dCD
F=B-E, G=B+E
Y3=AF((X1+Y1)*(X2+Y2)-C-D)
X3=AG(C-eD)
Z3=FG

Если не менять:
(x1,y1)+(x2,y2) = (x1y2+x2y1)/(1+dx1x2y1y2), (y1y2-ex1x2)/(1-dx1x2y1y2)

Q(X1/Z1, Y1/Z1) + P(X2,Y2)
X3 = Z1Z2(Z1^2*Z2^2 - dX1X2Y1Y2)(X1Y2+ Y1X2)
Y3 = Z1Z2(Z1^2*Z2^2 + dX1X2Y1Y2)(Y1Y2-eX1X2)
Z3 = (Z1^2*Z2^2 - dX1X2Y1Y2)(Z1^2*Z2^2 + dX1X2Y1Y2)
Обозначим
A=Z1Z2, B=A^2, C=X1X2, D=Y1Y2, E=dCD
F=B-E, G=B+E
X3=AF((X1+Y1)*(X2+Y2)-C-D)
Y3=AG(D-eC)
Z3=FG


11M+1S+7A
*/
static void ec_point_ed_add_p2p(ECC_Point* Q, ECC_Point* P, /* BNuint* px, BNuint* py, */BNuint* e, BNuint* d, MPCtx *ctx)
{
    BNuint A[ctx->asize] BN_ALIGN;
    BNuint C[ctx->asize] BN_ALIGN;
    BNuint D[ctx->asize] BN_ALIGN;
    if (P->z!=NULL)
        mp_mulm(ctx, Q->z, Q->z, P->z);// A = Z1Z2
    mp_mulm(ctx, C, Q->x, P->x);    // C = X1X2
    mp_mulm(ctx, D, Q->y, P->y);    // D = Y1Y2
    mp_addm(ctx, Q->x, Q->y, Q->x);
    mp_addm(ctx, Q->y, P->x, P->y);
    mp_mulm(ctx, Q->x, Q->x, Q->y); // (X1+Y1)*(X2+Y2)
    mp_subm(ctx, Q->x, Q->x, C);
    mp_subm(ctx, Q->x, Q->x, D);
    mp_mulm(ctx, Q->x, Q->x, Q->z);// X3=A((X1+Y1)*(X2+Y2)-C-D)
    mp_mulm(ctx, A, C, D);
    mp_mulm(ctx, A, A, d);// E=dCD
    if (e!=NULL)
        mp_mulm(ctx, C, C, e);
    mp_subm(ctx, Q->y, D, C);// D-eC
    mp_mulm(ctx, Q->y, Q->y, Q->z);// A(D-eC)
    mp_sqrm(ctx, D, Q->z);// B = A^2
    mp_subm(ctx, C, D, A);// F = B-E
    mp_addm(ctx, D, D, A);// G = B+E
    mp_mulm(ctx, Q->x, Q->x, C);// X3=AF((X1+Y1)*(X2+Y2)-C-D)
    mp_mulm(ctx, Q->y, Q->y, D);// Y3=AG(D-eC)
    mp_mulm(ctx, Q->z, C, D);//Z3 = FG
}
static inline void ec_point_ed_add_a2p(ECC_Point* Q, BNuint* px, BNuint* py, BNuint* e, BNuint* d, MPCtx *ctx)
{
    ECC_Point P = {px,py};
    ec_point_ed_add_p2p(Q, &P, e, d, ctx);
}
/*! \brief удвоение точек в поле скрученной кривой Эдвардса в проективных координатах

2(x,y) = (x^2-ey^2)/(1-dx^2y^2) , (2xy)/(1+dx^2y^2)
Заменой в знаменателе x^2+ey^2 = 1+dx^2y^2 получим:
2(x,y) = (x^2-ey^2)/(2-x^2-ey^2) , (2xy)/(x^2+ey^2)

X3 = (X^2 - eY^2)(X^2 + eY^2)
Y3 = 2XY(2Z^2 - X^2 - eY^2)
Z3 = (X^2 + eY^2)(2Z^2 - X^2 - eY^2)

Если не менять переменные
2(x,y) = (2xy)/(1+dx^2y^2), (y^2-ex^2)/(1-dx^2y^2)
Заменой в знаменателе ex^2+y^2 = 1+dx^2y^2 получим:
2(x,y) = (2xy)/(ex^2+y^2), (y^2-ex^2)/(2-ex^2-y^2)

X3 = 2XY(2Z^2 - Y^2 - eX^2)
Y3 = (Y^2 - eX^2)(Y^2 + eX^2)
Z3 = (Y^2 + eX^2)(2Z^2 - Y^2 - eX^2)


    \param P - точка в проективных координатах
    \param e - параметр кривой, если e=1 то в функцию передается NULL
5M + 3S+3A
*/
void ec_point_ed_dup(ECC_Point* P, BNuint* e, BNuint* d, MPCtx *ctx)
{
    BNuint A[ctx->asize] BN_ALIGN;
    BNuint B[ctx->asize] BN_ALIGN;

    mp_mulm(ctx, B, P->x, P->y);//
    mp_dubm(ctx, B, B);         // 2xy

    mp_sqrm(ctx, P->x, P->x); // A =x^2
    mp_sqrm(ctx, P->y, P->y); // B =y^2

    if (e!=NULL) {// != 1
        mp_mulm(ctx, P->x, P->x, e); // C=ax^2
    }
    mp_sqrm(ctx, P->z, P->z); // D =z^2
    mp_dubm(ctx, P->z, P->z); // G = 2z^2 ... -A-C

    mp_addm(ctx, A, P->y, P->x);    // E=A+C
    mp_subm(ctx, P->x, P->y, P->x); // F=A-C
    mp_mulm(ctx, P->y, P->x, A);    // X = E*F
    mp_subm(ctx, P->z, P->z, A);    // G = 2D -A-C = 2D-E

    mp_mulm(ctx, P->x, P->z, B);    // Y = 2xy*G
    mp_mulm(ctx, P->z, P->z, A);    // Z = E*G

}
/*! \brief Умножает точку на скрюченной эллиптической кривой Эдвардса на скаляр Q = kP
    Используется метод Left-to-Right типа Binary NAF \see Alg GECC 3.31
    сложение производится только в начале или в конце последовательности единиц
    \param P точка на эллиптической кривой задана в аффинных координатах (x,y,1)
 */
void ec_point_ed_mul(ECC_Point *Q, ECC_Point *P, BNuint * k, BNuint* e, BNuint* d, MPCtx* ctx)
{
    int sign=0;
    BNuint pn[ctx->asize] BN_ALIGN;
    bn_sub(pn, ctx->prime, P->x, ctx->size);// -(x,y) = (-x,y)
    int i = (ctx->size<<5);
    uint32_t kk = bn_bit_val(k, i-1)<<1 | bn_bit_val(k, i-2);
    if ((kk&3)==3){
        ec_point_ed_copy_a2p (Q, P->x, P->y, ctx);
        sign = 1;
    } else {
        ec_point_ed_infty(Q, ctx);
    }
    do {
        ec_point_ed_dup(Q, e, d, ctx);
        kk<<=1;
        if (i>=3) kk |= bn_bit_val(k, i-3);
        if ((kk&7)==3){
            ec_point_ed_add_a2p(Q,P->x, P->y, e, d, ctx);
            sign = 1;
        } else
        if ((kk&6)==4){
            if (sign){
                ec_point_ed_add_a2p(Q,pn, P->y, e, d, ctx);
                sign = 0;
            } else {
                ec_point_ed_add_a2p(Q,P->x, P->y, e, d, ctx);
            }
        }
    } while (--i);
}

/*! \brief Умножает точку на эллиптической кривой на число Q = kP
    Используется метод Left-to-Right \see Alg 3.27
    \param P точка на эллиптической кривой задана в аффинных координатах (x,y,1)
 */
void ec_point_ed_mul_27(ECC_Point *Q, ECC_Point *P, BNuint * k, BNuint* e,BNuint* d, MPCtx* ctx)
{
    int i=ctx->size;
    while (i>0 && k[i-1]==0) i--;
    i=(i<<BN_BIT_LOG)-1;
    while (i>=0 && !bn_bit_test(k, i)) i--;
    if (i<0) {
        ec_point_ed_infty(Q, ctx);
    } else {
        ec_point_ed_copy_a2p(Q, P->x, P->y, ctx);
        i--;
        for (; i>= 0; i--){
            ec_point_ed_dup(Q, e,d, ctx);
            if (bn_bit_test(k, i))
                ec_point_ed_add_a2p(Q,P->x, P->y, e,d, ctx);
        }
    }
}
/*! \brief Умножает точку на эллиптической кривой на число Q = kP
    Используется метод Монтгомери "ladder"
    \param P точка на эллиптической кривой задана в аффинных координатах (x,y,1)
 */
void ec_point_ed_mul_ladder(ECC_Point *P, ECC_Point *G, BNuint * k, BNuint* e,BNuint* d, MPCtx* ctx)
{
    BNuint v[3][ctx->asize] BN_ALIGN;
    ECC_Point Q = {v[0],v[1],v[2]};
    int i=ctx->size;
    while (i>0 && k[i-1]==0) i--;
    i=(i<<BN_BIT_LOG)-1;
    while (i>=0 && !bn_bit_test(k, i)) i--;

    ec_point_ed_copy_a2p(&Q, G->x, G->y, ctx);
    ec_point_ed_copy_a2p( P, G->x, G->y, ctx);
//    ec_point_ed_infty(P, ctx);
    register ECC_Point *p,*q=&Q;
    for (i--; i>= 0; i--){
        ec_point_ed_dup(q, e,d, ctx);
        if (bn_bit_test(k, i)) {// todo swap (q,p)
            q = &Q, p =  P;
        } else {
            q =  P, p = &Q;
        }
        ec_point_ed_add_p2p(p,q, e,d, ctx);
    }
}


/*! \brief Преобразование точки из проективных координат в афинные координаты в поле скрюченной кривой Эдвардса

x = X/Z, y=Y/Z
\sa ec_point_affine
*/
void ec_point_ed_affine(BNuint *qx, BNuint *qy, ECC_Point *Q, MPCtx* ctx)
{
    BNuint z1[ctx->asize] BN_ALIGN;

    if (qy) {
        mp_divm(ctx, z1, NULL, Q->z);
        mp_mulm(ctx, qx, Q->x, z1);
        mp_mulm(ctx, qy, Q->y, z1);
        mp_modp(ctx, qx, qx);
		mp_modp(ctx, qy, qy);
    } else {
        mp_divm(ctx, qx, Q->x, Q->z);
        mp_modp(ctx, qx, qx);
    }
}
/*! \brief Сравнение точек */
int ec_point_ed_equal(BNuint *qx, BNuint *qy, ECC_Point *Q, MPCtx* ctx)
{
    BNuint v[ctx->asize] BN_ALIGN;
//    # x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
    if(qx) {
        mp_mulm(ctx, v, qx, Q->z);
        mp_subm(ctx, v, v, Q->x);
        mp_modp(ctx, v, v);
        if(!bn_is_zero(v, ctx->size))
            return 0;
    }
    if(qy) {
        mp_mulm(ctx, v, qy, Q->z);
        mp_subm(ctx, v, v, Q->y);
        mp_modp(ctx, v, v);
        if(!bn_is_zero(v, ctx->size))
            return 0;
    }
    return 1;
}
/*! \brief Функция проверяет находится ли точка {Q.x,Q.y, 1} на скрученной эллиптической кривой Эдвардса
    Метод проверки - подставить в уравнение проверить тождество.

eu^2 + v^2 = 1 + du^2v^2
v^2(1 - du^2) == 1 - eu^2

    \param x (u)- параметр задан
    \param y (v) - параметр восстанавливается
    \param e - постоянная величина характризует кривую
    \param d - постоянная величина характризует кривую


 */
int ec_point_ed_verify(BNuint* qx, BNuint* qy, BNuint* e, BNuint* d, MPCtx* ctx)
{
    BNuint p1[ctx->asize] BN_ALIGN;
    BNuint x2[ctx->asize] BN_ALIGN;
    BNuint x3[ctx->asize] BN_ALIGN;
    bn_move(p1, ctx->prime, ctx->size);
        p1[0]+=1;
    mp_sqrm(ctx, x2, qx);
    if (e==NULL){// a=1
        mp_subm(ctx, x3, p1, x2);// 1-u^2 === prime+1 - u^2
    } else {
        mp_mulm(ctx, x3,  e, x2);
        mp_subm(ctx, x3, p1, x3);// 1-eu^2 === prime+1 - eu^2
    }
    mp_modp(ctx, x3, x3);

    mp_mulm(ctx, x2,  d, x2);
    mp_subm(ctx, x2, p1, x2);// 1-du^2 === prime+1 - du^2

    mp_sqrm(ctx, p1, qy);
    mp_mulm(ctx, x2, p1, x2);
    mp_modp(ctx, x2, x2);

    int res = bn_equ(x2, x3, ctx->size);
    return res;
}
/*! \brief преобразование координат из формы скрученной кривой Эдвардса в каноническую форму
    Предполагается использовать эту функцию при финальном преобразовании вместо \b ec_point_affine()
    Это значит что расчитывать координату Y может не требоваться.
    Преобразование производится из проективных координат в афинные.

 (x,y) = s(Z+V)/(Z-V) +t, s(Z+V)Z/(Z-V)U
*/
void ec_point_ed2w(ECC_Point* Q, BNuint* qx, /* BNuint* qy, */BNuint* s, BNuint* t, MPCtx* ctx)
{
    BNuint z[ctx->asize] BN_ALIGN;
    mp_addm(ctx, qx, Q->z, Q->y);
    mp_mulm(ctx, qx, qx, s);
    mp_subm(ctx, z, Q->z, Q->y);
    mp_divm(ctx, qx, qx, z);
    mp_addm(ctx, qx, qx, t);
}
/*! \brief преобразование из аффинных координат канонической формы Вейерштрасса в форму Монтгомери

*/

/*! \brief преобразование координат из формы Монтгомери в каноническую формы Вейерштрасса в проективные координаты
	x'=sX+tZ, y'=sY
*/

/*! \brief преобразование координат из канонической формы Вейерштрасса
    в форму скрученной кривой Эдвардса в проективные координаты (U/Z,V/Z)
    (u,v)=(x-t)/y, ((x-t)-s)/((x-t)+s)

x=x-t
u=(x+s)*x
v=(x-s)*y
z=(x+s)*y

*/
void ec_point_w2ed(ECC_Point* Q, BNuint* qx, BNuint* qy, BNuint* s, BNuint* t, MPCtx* ctx)
{
	mp_subm(ctx, Q->x, qx, t);
	mp_subm(ctx, Q->y, Q->x, s);
	mp_addm(ctx, Q->z, Q->x, s);
	mp_mulm(ctx, Q->x, Q->x, Q->z);
	mp_mulm(ctx, Q->y, Q->y, qy);
	mp_mulm(ctx, Q->z, Q->z, qy);
}
/*! \brief преобразование переменных из e,d в s,t
    s = (e-d)/4 mod p
    t = (e+d)/6 mod p
*/
void ec_point_ed2st(BNuint* s, BNuint* t, BNuint* e, BNuint* d, MPCtx* ctx)
{
    BNuint v[ctx->asize] BN_ALIGN;
	mp_subm(ctx, s, e, d);
	mp_hlvm(ctx, s);
	mp_hlvm(ctx, s);
//	mp_modp(ctx, s, s);
	mp_addm(ctx, t, e, d);
	bn_set_ui(v, 6, ctx->size);
	mp_divm(ctx, t, t, v);
//	mp_modp(ctx, t, t);
}
/*! \brief проверка корня уравнения
(t,0) - должно быть корнем
*/
int ec_point_ed_root(BNuint* s, BNuint* t, BNuint* a, BNuint* b, const MPCtx* ctx)
{
    extern int ec_point_verify(BNuint* qx, BNuint* qy, BNuint* a, BNuint* b, const MPCtx* ctx);
    BNuint qx[ctx->asize] BN_ALIGN;
    BNuint qy[ctx->asize] BN_ALIGN;

    if (a==(void*)-3) {
        printf("\na = -3");
    } else {
        mp_subm(ctx, qx, ctx->prime, b);
        mp_mulm_ui(ctx, qx, qx, 3);
        mp_mulm_ui(ctx, qy, a, 2);

    }
    mp_divm(ctx, qx, qx,qy);
        printf("\nt = 0x"); bn_print (qx, ctx->size);

    bn_set_0(qy, ctx->size);
    bn_move (qx, t, ctx->size);

    return ec_point_verify(qx,qy, a,b, ctx);
}
/*! \brief сравнение двух точек в проективных координатах */

/*! \brief восстанавливает значение qv по qu для скрученной эллиптической кривой Эдвардса

eu^2 + v^2 = 1 + du^2v^2

y^2 = (1-eu^2)/(1-du^2)

    \param u - параметр задан
    \param v - параметр восстанавливается
    \param e - постоянная величина характризует кривую
    \param d - постоянная величина характризует кривую

 */
void ec_point_ed_y(BNuint* qx, BNuint* qy, BNuint* e, BNuint* d, MPCtx* ctx)
{
    BNuint p1[ctx->asize] BN_ALIGN;
    BNuint x2[ctx->asize] BN_ALIGN;
    BNuint x3[ctx->asize] BN_ALIGN;
    bn_move(p1, ctx->prime, ctx->size);
        p1[0]+=1;
    mp_sqrm(ctx, x2, qx);
    if (e==(void*)1){// a=1
        mp_subm(ctx, x3, p1, x2);// 1-u^2 === prime+1 - u^2
    } else {
        mp_mulm(ctx, x3,  e, x2);
        mp_subm(ctx, x3, p1, x3);// 1-u^2 === prime+1 - eu^2
    }
    mp_mulm(ctx, x2,  d, x2);
    mp_subm(ctx, x2, p1, x2);// 1-u^2 === prime+1 - eu^2

    mp_invm(ctx, x2, x2);
    mp_mulm(ctx, x2, x3, x2);
    mp_modp(ctx, x2, x2);

    if ((ctx->prime[0]&3) == 3){
        /// для проверки подписи оба варианта подходят +y и -y
        mp_srtm(ctx, qy, x2);
        //mp_modp(ctx, qy, qy);
    }
}
/*! \brief проверка преобразования коэффициентов уравнения a,b кривой в форме Вейерштрасса
    из коэффициентов скрюченной кривой Эдвардса, по модулю P

    Формулы из МР 26. 2.002-2018
    a = s^2 - 3t^2, где s = (e-d)/4, t = (e+d)/6
    b = 2t^3 - ts^2, b= -t(a+t^2), t - корень
Вместо этого считаем исключая инверсию:

    4*12a= 3(e-d)^2+4(e+d)^2
    6*9*16b= (e+d)(8(e+d)^2 - 9(e-d)^2)
    */
int ec_point_ed_ab(BNuint* a, BNuint* b, BNuint* e, BNuint* d, MPCtx* ctx)
{
    BNuint v[ctx->asize] BN_ALIGN;
    BNuint s[ctx->asize] BN_ALIGN;
    BNuint t[ctx->asize] BN_ALIGN;
    if (e!=NULL) {
        mp_subm(ctx, s, e, d);
        mp_addm(ctx, t, e, d);
    } else {
        bn_move(t, ctx->prime, ctx->size);
        t[0]++;
        mp_subm(ctx, s, t, d);
        mp_addm(ctx, t, t, d);
    }
    mp_sqrm(ctx, s, s);
    mp_sqrm(ctx, t, t);

    mp_mulm_ui(ctx, s, s, 3);
    mp_mulm_ui(ctx, t, t, 4);
    mp_subm(ctx, s, s, t);
    if (a==(void*)-3) {
        bn_set_0(t, ctx->size);
        t[0] = 3*48;
        mp_subm(ctx, t, ctx->prime, t);
    } else {
        mp_mulm_ui(ctx, t, a, 48);
    }
    mp_subm(ctx, s, s, t);
//    mp_modp(ctx, s, s);
    printf("\ns =  0x"); bn_print (s, ctx->size);
    int res = bn_is_zero(s, ctx->size);
    if (!res) return 0;
    if (e!=NULL) {
        mp_subm(ctx, s, e, d);
        mp_addm(ctx, v, e, d);
    } else {
        bn_move(t, ctx->prime, ctx->size);
        t[0]++;
        mp_subm(ctx, s, t, d);
        mp_addm(ctx, t, t, d);
    }
    mp_sqrm(ctx, s, s);
    mp_sqrm(ctx, t, v);

    mp_mulm_ui(ctx, s, s, 9);
    mp_mulm_ui(ctx, t, t, 8);
    mp_subm(ctx, t, t, s);
    mp_mulm(ctx, t, t, v);

    mp_mulm_ui(ctx, s, b, 6*9*16);
    mp_subm(ctx, s, s, t);
//    mp_modp(ctx, s, s);
    printf("\ns =  0x"); bn_print (s, ctx->size);

    return bn_is_zero(s, ctx->size);

}

//void mp_divm(const MPCtx* const ctx, BNuint* q, BNuint* a, BNuint* b);
void ecc_edwards_test()
{
    ECC_Curve curve;

    if (1 && ecc_curve_find (&curve, EC_TC26_GOST_3410_2012_256_A)){
        char e0[] = "01";
        char d0[] = "0605F6B7C183FA81578BC39CFAD51813"
                    "2B9DF62897009AF7E522C32D6DC7BFFB";
        char q0[] = "40000000000000000000000000000000"
                    "0FD8CDDFC87B6635C115AF556C360C67";
        char u0[] = "0D";
        char v0[] = "60CA1E32AA475B348488C38FAB07649C"
                    "E7EF8DBE87F22E81F92B2592DBA300E7";
        MPValue e; e.value=NULL;mp_alloc(curve.ctx, &e); mp_hex2bin(curve.ctx, &e, e0);
        MPValue d; mp_alloc(curve.ctx, &d); mp_hex2bin(curve.ctx, &d, d0);
        MPValue q; mp_alloc(curve.ctx, &q); mp_hex2bin(curve.ctx, &q, q0);
        MPValue u; mp_alloc(curve.ctx, &u); mp_hex2bin(curve.ctx, &u, u0);
        MPValue v; mp_alloc(curve.ctx, &v); mp_hex2bin(curve.ctx, &v, v0);
        printf("\ne =  0x"); bn_print (e.value, curve.ctx->size);
        printf("\nd =  0x"); bn_print (d.value, curve.ctx->size);
        printf("\nq =  0x"); bn_print (q.value, curve.ctx->size);
        printf("\nu =  0x"); bn_print (u.value, curve.ctx->size);
        printf("\nv =  0x"); bn_print (v.value, curve.ctx->size);
// точка принадлежит кривой эдвардса
        if(ec_point_ed_verify(u.value, v.value, e.value, d.value, curve.ctx)){
            printf("\n ec point verifyed");
        } else
            _Exit(1);

        MPCtx *ctq = mp_ctx_new(256);
        bn_hex2bin (ctq->prime, ctq->size, q0);
        //ctq->_prime= bn_alloc(ctq->asize);
        //bn_hex2bin (ctq->_prime, ctq->size, q4);
        ctq->reduction = curve.ctq->reduction;

        BNuint a[ctq->asize] BN_ALIGN;
        BNuint x[ctq->asize] BN_ALIGN;
        BNuint k[ctq->asize] BN_ALIGN;
        //bn_shl(ctq->prime, ctq->prime, 1, ctq->size);

        mp_invm(ctq, x, d.value);
        printf("\nv   = 0x"); bn_print (d.value, ctq->size);
        printf("\ninv = 0x"); bn_print (x, ctq->size);
        mp_mulm(ctq, x, x, d.value);
        mp_modp(ctq, x, x);
        if (bn_is_one(x, ctq->size)) {
            printf("\n mp inversion mod q verifyed");
        } else {
            printf("\nx   = 0x"); bn_print (x, ctq->size);
            printf("\n mp inversion mod q fail....");
        }
        bn_hex2bin (a, ctq->size, v0);
        int i;
        for (i=0; i<0;i++){
            a[0]++;
            mp_divm(ctq, x, NULL, a);
//            mp_invm(ctq, x, a);
//            printf("\n~x = 0x"); bn_print (x, ctq->size);
            mp_mulm(ctq, x, x, a);
            mp_modp(ctq, x, x);
            printf("\n x = 0x"); bn_print (x, ctq->size);
            //if (!bn_is_one(x, ctq->size))break;
        }
        printf("EQU=%d\n", i);

        mp_invm(ctq, x, d.value);


        MPCtx *ctx = curve.ctq;
        mp_invm(ctx, x, d.value);
        mp_mulm(ctx, x, x, d.value);
        mp_modp(ctx, x, x);
        if (bn_is_one(x, ctq->size)) {
            printf("\n mp inversion mod p verifyed");
        }

        int res = ec_point_ed_ab(curve.a, curve.b, e.value, d.value, curve.ctx);
        if (res) printf("\nAB->ED ok\n");

		// следующий тест: преобразовать к виду (x,y)=>(u,v) и сравнить
		ECC_Point Q;
		ECC_Point R;
        BNuint vv[6][curve.ctx->asize] BN_ALIGN;
        BNuint qx[curve.ctx->asize] BN_ALIGN;
        BNuint qy[curve.ctx->asize] BN_ALIGN;
        BNuint t[curve.ctx->asize] BN_ALIGN;
        BNuint s[curve.ctx->asize] BN_ALIGN;
        Q.x = vv[0], Q.y = vv[1], Q.z = vv[2];
        R.x = vv[3], R.y = vv[4], R.z = vv[5];
// 1. предлагаем функцию быстрого редуцирования
// t=(e+d)/6, s=(e-d)/4
        ec_point_ed2st(s,t,e.value,d.value, curve.ctx);

        if (ec_point_ed_root(s, t, curve.a, curve.b, curve.ctx)) {
            printf("\nW: root (t,0) verifyed\n");
            printf("\nt = 0x"); bn_print (t, curve.ctx->size);
        }
		printf("\nGx= 0x"); bn_print (curve.G.x, curve.ctx->size);
		ec_point_w2ed(&Q, curve.G.x, curve.G.y, s,t, curve.ctx);

		ec_point_ed_affine(qx, qy, &Q, curve.ctx);
        if(ec_point_ed_verify(qx, qy, e.value, d.value, curve.ctx)){
            printf("\n ec point verifyed2");
        } else
            _Exit(2);
		//ec_point_ed_mul(&R, &Q, k, e.value, d.value, curve.ctx);
        ec_point_ed_dup(&Q, e.value, d.value, curve.ctx);
		ec_point_ed_affine(qx, qy, &Q, curve.ctx);
        if(ec_point_ed_verify(qx, qy, e.value, d.value, curve.ctx)){
            printf("\n ec point verifyed3");
        } else
            _Exit(3);
#if 0
        ec_point_ed_infty(&Q, curve.ctx);
        ec_point_ed_add_a2p(&Q, u.value, v.value, e.value, d.value, curve.ctx);
#else
        ec_point_ed_copy_a2p(&Q, u.value, v.value, curve.ctx);
#endif
        ec_point_ed_add_a2p(&Q, u.value, v.value, e.value, d.value, curve.ctx);
        ec_point_ed_add_a2p(&Q, u.value, v.value, e.value, d.value, curve.ctx);
        //ec_point_ed_dup(&Q, e.value, d.value, curve.ctx);
		ec_point_ed_affine(qx, qy, &Q, curve.ctx);
        if(ec_point_ed_verify(qx, qy, e.value, d.value, curve.ctx)){
            printf("\nu = 0x"); bn_print (qx, curve.ctx->size);
            printf("\n ec point verifyed4");
        } else
            _Exit(4);
		bn_set_ui(k, 3, curve.ctx->size);
		ec_point_ed_copy_a2p(&Q, u.value,v.value, curve.ctx);
		ec_point_ed_mul_27(&R, &Q, k, e.value, d.value, curve.ctx);
		ec_point_ed_affine(qx, qy, &R, curve.ctx);
        if(ec_point_ed_verify(qx, qy, e.value, d.value, curve.ctx)){
            printf("\nu = 0x"); bn_print (qx, curve.ctx->size);
            printf("\n ec point verifyed5");
        } else
            _Exit(5);

		ec_point_ed_mul_ladder(&R, &Q, k, e.value, d.value, curve.ctx);
		ec_point_ed_affine(qx, qy, &R, curve.ctx);
        if(ec_point_ed_verify(qx, qy, e.value, d.value, curve.ctx)){
            printf("\nu = 0x"); bn_print (qx, curve.ctx->size);
            printf("\n ec point verifyed6");
        } else
            _Exit(6);

		ec_point_ed_mul(&R, &Q, k, e.value, d.value, curve.ctx);
		ec_point_ed_affine(qx, qy, &R, curve.ctx);
        if(ec_point_ed_verify(qx, qy, e.value, d.value, curve.ctx)){
            printf("\nu = 0x"); bn_print (qx, curve.ctx->size);
            printf("\n ec point verifyed7");
        } else
            _Exit(7);

		printf("\nu = 0x"); bn_print (qx, curve.ctx->size);
		printf("\nv = 0x"); bn_print (qy, curve.ctx->size);
		ec_point_ed2w(&Q, qx, /* NULL, */s,t, curve.ctx);
		printf("\nx = 0x"); bn_print (qx, curve.ctx->size);
		printf("\nGx= 0x"); bn_print (curve.G.x, curve.ctx->size);
        printf("\n");
/*! // хождение по кривой
eu^2 + v^2 = 1 + du^2v^2
Err = e(x+1)^2 + (y+dy)^2 - 1 - d(x+1)^2(y+dy) = (1-/+2x)(e - dy^2)
Err = (x+1)^2(e-dy^2) + y^2 - 1;
*/

        ecc_curve_free (&curve);
	}
}
