/* ECC */
#ifndef ECC_H
#define ECC_H
#include "mp.h"

/*! ������������� ����� EC � ����������� ����������� */
typedef struct _ECC_Point ECC_Point;
struct _ECC_Point {
    BNuint *x, *y, *z;
};
/*! ������������� ����� EC � ���������� ����������� */
typedef struct _ECC_PointCh ECC_PointCh;
struct _ECC_PointCh {
    BNuint *x, *y, *z, *z2, *z3;
};
/*! ������������� ����� EC � �������� ����������� */
typedef struct _ECC_PointA ECC_PointA;
struct _ECC_PointA {
    BNuint *x, *y;
};
/*! ������������� ����� EC � ������������ ����������� ����������, */
typedef struct _ECC_PointM ECC_PointM;
struct _ECC_PointM {
    BNuint *x, *z;
};
/*! ������������� ����� EC � ����������� �����������
������������ ��� ���������� ����� ������ ��������
x = X/Z, y = Y/Z, x*y = T/Z
 */
typedef struct _ECC_PointE ECC_PointE;
struct _ECC_PointE {
    BNuint *x, *y, *z, *t;
};
#define NAF_WINDOW   4
//#define NAF_SIZE    (1<<(NAF_WINDOW-2))
#define FIX_BIT_LOG  2
#define FIX_WINDOW   4
#define FIX_OFFSET  (1<<FIX_WINDOW)
#define FIX_SIZE    (FIX_OFFSET -1) // 2 ������� �� 15 ����� 0 �� ������

typedef struct _ECC_Curve ECC_Curve;
struct _ECC_Curve {
    const char* name;
//    int bn_size;
    BNuint *a,*b;//,*p,*n; e,d - ��� ������ ��������
    MPCtx *ctx;
    MPCtx *ctq;
    ECC_Point G;    // �����-���������
    ECC_Point P[1<<(NAF_WINDOW-2)];// ����������� ��� ������ NAF w<=4
    ECC_Point F0[FIX_SIZE];// ����������� ��� ������ Fixed-base w=4
    ECC_Point F1[FIX_SIZE];// ����������� ��� ������ Fixed-base w=4
    ECC_Point F2[FIX_SIZE];// ����������� ��� ������ Fixed-base w=4
    ECC_Point F3[FIX_SIZE];// ����������� ��� ������ Fixed-base w=4
};

typedef struct _ECC_Params ECC_Params;
struct _ECC_Params {
  const char *name;             //!< ��������� ������������� ������������� ������
  int nbits;                    //!< ����� ��� � prime
  bool fips;                    //!< True if this is a FIPS140-2 approved curve
//  bool minus3;                  //!< a=p-3 �� a==NULL
  MPReduction fast_reduction_p; //!< ������� �������� ������������� �� prime
  MPReduction fast_reduction_n; //!< ������� �������� ������������� �� n
  const char *p;                //!< ������� �����
  const char *a, *b;            //!< W: y^2 = x^3 + a*x + b ���
  //Edw: x^2+ay^2=1+bx^2y^2
  //M:   by^2 = x^3+ax^2+x
  const char *n;                //!< The order of the base point
  const char *g_x, *g_y;        //!< Base point
};


void ec_point_copy_a2j(ECC_Point* Q, BNuint* px, BNuint* py, MPCtx *ctx);
void ec_point_copy_j2j(ECC_Point* Q, ECC_Point* P, MPCtx *ctx);
void ec_point_dup (ECC_Point* P, BNuint* a, MPCtx *ctx);
void ec_point_mul (ECC_Point *Q, ECC_Point *P, BNuint * k, BNuint* a, MPCtx* ctx);
void ec_point_add_a2j(ECC_Point *Q, BNuint* px, BNuint* py, MPCtx * ctx);
void ec_point_affine(BNuint *qx, BNuint *qy, ECC_Point *Q, MPCtx* ctx);
void ec_point_ed_affine(BNuint *qx, BNuint *qy, ECC_Point *Q, MPCtx* ctx);
void ec_point_affine_vec(ECC_Point *Q, int n, MPCtx* ctx);
void ec_point_y(BNuint* qx, BNuint* qy, BNuint* a, BNuint* b, MPCtx* ctx);
int  ec_point_verify(BNuint* qx, BNuint* qy, BNuint* a, BNuint* b, const MPCtx* ctx);

int  ecc_public_key_verify(BNuint* qx, BNuint* qy, BNuint* d, ECC_Curve* curve);
void ecc_public_key(BNuint* qx, BNuint* qy, BNuint* d, ECC_Curve* curve);
void ecc_gen_key(BNuint* k, MPCtx * ctx);

int  ecc_curve_find(ECC_Curve *curve, int id);
void ecc_curve_free(ECC_Curve *curve);
#endif // ECC_H
