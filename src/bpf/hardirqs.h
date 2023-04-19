#ifndef __HARDIRQS_H
#define __HARDIRQS_H

struct irq_key
{
    __u8 name[32];
};

struct info
{
    __u64 count;
    __u64 sum;
};

struct irq_key _key = {};
struct info _info = {};
#endif