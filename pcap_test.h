#pragma once
#include<stdint.h>

struct ETH{
    uint8_t D_Mac[6];
    uint8_t S_Mac[6];
    uint16_t EType;
}__attribute__((packed));

struct IP{
    uint8_t VER_IHL;
    uint8_t TOS;
    uint16_t TotalLen;
    uint16_t Identification;
    uint16_t Flags;
    uint8_t Ttl;
    uint8_t Protocol;
    uint16_t Checksum;
    uint8_t S_IP[4];
    uint8_t D_IP[4];
    uint8_t *Options;
}__attribute__((packed));

struct TCP{
    uint16_t S_Port;
    uint16_t D_Port;
    uint32_t Sequence_Num;
    uint32_t Acknowledge_Num;
    uint16_t Flags;
    uint16_t Window_Size;
    uint16_t Checksum;
    uint16_t Urgent_ptr;
    uint8_t *Options;
    uint8_t *Data;
}__attribute__((packed));
