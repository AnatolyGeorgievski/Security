/*! таблица для редуцирования после умножения старшую часть по таблице добавить к остатку */
const uint8_t gf2m_64[] = {
0x00, 0x1B, 0x36, 0x2D,
0x6C, 0x77, 0x5A, 0x41,
0xD8, 0xC3, 0xEE, 0xF5,
0xB4, 0xAF, 0x82, 0x99,
};
uint16_t gf2m_128[] = {
//GF2m-128 POLY=0x0087
0x0000, 0x0087, 0x010E, 0x0189,
0x021C, 0x029B, 0x0312, 0x0395,
0x0438, 0x04BF, 0x0536, 0x05B1,
0x0624, 0x06A3, 0x072A, 0x07AD,
0x0870, 0x08F7, 0x097E, 0x09F9,
0x0A6C, 0x0AEB, 0x0B62, 0x0BE5,
0x0C48, 0x0CCF, 0x0D46, 0x0DC1,
0x0E54, 0x0ED3, 0x0F5A, 0x0FDD,
0x10E0, 0x1067, 0x11EE, 0x1169,
0x12FC, 0x127B, 0x13F2, 0x1375,
0x14D8, 0x145F, 0x15D6, 0x1551,
0x16C4, 0x1643, 0x17CA, 0x174D,
0x1890, 0x1817, 0x199E, 0x1919,
0x1A8C, 0x1A0B, 0x1B82, 0x1B05,
0x1CA8, 0x1C2F, 0x1DA6, 0x1D21,
0x1EB4, 0x1E33, 0x1FBA, 0x1F3D,
0x21C0, 0x2147, 0x20CE, 0x2049,
0x23DC, 0x235B, 0x22D2, 0x2255,
0x25F8, 0x257F, 0x24F6, 0x2471,
0x27E4, 0x2763, 0x26EA, 0x266D,
0x29B0, 0x2937, 0x28BE, 0x2839,
0x2BAC, 0x2B2B, 0x2AA2, 0x2A25,
0x2D88, 0x2D0F, 0x2C86, 0x2C01,
0x2F94, 0x2F13, 0x2E9A, 0x2E1D,
0x3120, 0x31A7, 0x302E, 0x30A9,
0x333C, 0x33BB, 0x3232, 0x32B5,
0x3518, 0x359F, 0x3416, 0x3491,
0x3704, 0x3783, 0x360A, 0x368D,
0x3950, 0x39D7, 0x385E, 0x38D9,
0x3B4C, 0x3BCB, 0x3A42, 0x3AC5,
0x3D68, 0x3DEF, 0x3C66, 0x3CE1,
0x3F74, 0x3FF3, 0x3E7A, 0x3EFD,
0x4380, 0x4307, 0x428E, 0x4209,
0x419C, 0x411B, 0x4092, 0x4015,
0x47B8, 0x473F, 0x46B6, 0x4631,
0x45A4, 0x4523, 0x44AA, 0x442D,
0x4BF0, 0x4B77, 0x4AFE, 0x4A79,
0x49EC, 0x496B, 0x48E2, 0x4865,
0x4FC8, 0x4F4F, 0x4EC6, 0x4E41,
0x4DD4, 0x4D53, 0x4CDA, 0x4C5D,
0x5360, 0x53E7, 0x526E, 0x52E9,
0x517C, 0x51FB, 0x5072, 0x50F5,
0x5758, 0x57DF, 0x5656, 0x56D1,
0x5544, 0x55C3, 0x544A, 0x54CD,
0x5B10, 0x5B97, 0x5A1E, 0x5A99,
0x590C, 0x598B, 0x5802, 0x5885,
0x5F28, 0x5FAF, 0x5E26, 0x5EA1,
0x5D34, 0x5DB3, 0x5C3A, 0x5CBD,
0x6240, 0x62C7, 0x634E, 0x63C9,
0x605C, 0x60DB, 0x6152, 0x61D5,
0x6678, 0x66FF, 0x6776, 0x67F1,
0x6464, 0x64E3, 0x656A, 0x65ED,
0x6A30, 0x6AB7, 0x6B3E, 0x6BB9,
0x682C, 0x68AB, 0x6922, 0x69A5,
0x6E08, 0x6E8F, 0x6F06, 0x6F81,
0x6C14, 0x6C93, 0x6D1A, 0x6D9D,
0x72A0, 0x7227, 0x73AE, 0x7329,
0x70BC, 0x703B, 0x71B2, 0x7135,
0x7698, 0x761F, 0x7796, 0x7711,
0x7484, 0x7403, 0x758A, 0x750D,
0x7AD0, 0x7A57, 0x7BDE, 0x7B59,
0x78CC, 0x784B, 0x79C2, 0x7945,
0x7EE8, 0x7E6F, 0x7FE6, 0x7F61,
0x7CF4, 0x7C73, 0x7DFA, 0x7D7D,
};
