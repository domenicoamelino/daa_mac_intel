
/* GCC inline assembly version for Linux64 */

#include "miracl.h"


mr_small muldiv(mr_small a,mr_small b,mr_small c,mr_small m,mr_small *rp)
{
    mr_small q;
    double istante1 = mach_absolute_time( ) ;

    __asm__ __volatile__ (
    "movq %1,%%rax\n"
    "mulq %2\n"
    "addq %3,%%rax\n"
    "adcq $0,%%rdx\n"
    "divq %4\n"
    "movq %5,%%rbx\n"
    "movq %%rdx,(%%rbx)\n"
    "movq %%rax,%0\n"
    : "=m"(q)
    : "m"(a),"m"(b),"m"(c),"m"(m),"m"(rp)
    : "rax","rbx","memory"
    );

    double istante2 = mach_absolute_time( );
        double buff = istante2-istante1;
        if(buff > muldiv_time) muldiv_time = buff;

    muldiv_count++;

    return q;
}

mr_small muldvm(mr_small a,mr_small c,mr_small m,mr_small *rp)
{

    mr_small q;

    double istante1 = mach_absolute_time( );


    __asm__ __volatile__ (
    "movq %1,%%rdx\n"
    "movq %2,%%rax\n"
    "divq %3\n"
    "movq %4,%%rbx\n"
    "movq %%rdx,(%%rbx)\n"
    "movq %%rax,%0\n"
    : "=m"(q)
    : "m"(a),"m"(c),"m"(m),"m"(rp)
    : "rax","rbx","memory"
    );


    double istante2 = mach_absolute_time( );
        double buff = istante2-istante1;

    muldvm_count++;


        if(buff > muldvm_time) muldvm_time = buff;
    return q;
}

mr_small muldvd(mr_small a,mr_small b,mr_small c,mr_small *rp)
{

    mr_small q;

    double istante1 = mach_absolute_time( );


    __asm__ __volatile__ (
    "movq %1,%%rax\n"
    "mulq %2\n"
    "addq %3,%%rax\n"
    "adcq $0,%%rdx\n"
    "movq %4,%%rbx\n"
    "movq %%rax,(%%rbx)\n"
    "movq %%rdx,%0\n"
    : "=m"(q)
    : "m"(a),"m"(b),"m"(c),"m"(rp)
    : "rax","rbx","memory"
    );


    double istante2 = mach_absolute_time( );
    double buff = istante2-istante1;

    muldvd_count++;


        if(buff > muldvd_time) muldvd_time = buff;
    return q;
}

void muldvd2(mr_small a,mr_small b,mr_small *c,mr_small *rp)
{

    double istante1 = mach_absolute_time( );


    __asm__ __volatile__ (
    "movq %0,%%rax\n"
    "mulq %1\n"
    "movq %2,%%rbx\n"
    "addq (%%rbx),%%rax\n"
    "adcq $0,%%rdx\n"
    "movq %3,%%rsi\n"
    "addq (%%rsi),%%rax\n"
    "adcq $0,%%rdx\n"
    "movq %%rax,(%%rsi)\n"
    "movq %%rdx,(%%rbx)\n"
    : 
    : "m"(a),"m"(b),"m"(c),"m"(rp)
    : "rax","rbx","rsi","memory"
    );
    

    double istante2 = mach_absolute_time( );
    double buff = istante2-istante1;


        if(buff > muldvd2_time) muldvd2_time = buff;

    muldvd2_count++;
}

