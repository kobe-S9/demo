#ifndef _CHECK_
#define _CHECK_

#include "header.p4"

control Check(
    inout headers hdr,
    inout metadata meta) {

    
    bit<32> bitmapResult = 0x0;


    action read_Multi_md() {
        bit<32>   bitmapR;
        bit<32>   counterR;
        bit<1>    ECNR;
        bit<32>   SeqNumR;

        meta.offset = 0;

        meta.index = hdr.Multi.index;
        meta.valueIndex = hdr.Multi.index * 4;

        bitmap_reg.read(bitmapR, meta.index);
        meta.bitmap = bitmapR;
        
        counter_reg.read(counterR, meta.index);
        meta.counterNow = counterR;

        ECN_reg.read(ECNR, meta.index);
        meta.ECN = ECNR;

    }

   action check_Bitmap(bit<32> bitmap) {
        meta.ifaggregation = bitmap & meta.bitmap;
        meta.bitmap = meta.bitmap | bitmap;
    }

    table readMultimd {
        key = {
            hdr.Multi.isACK : exact;
        }
        actions = {
            read_Multi_md;
        }
        size = 1024;
        default_action = read_Multi_md();
    }

    table checkBitmap {
        key = {
            hdr.Multi.bitmap : ternary;
        }
        actions = {
            check_Bitmap;
        }
        const entries = {
            1  &&& 0x1f : check_Bitmap(1 << 0);
            2  &&& 0x1f : check_Bitmap(1 << 1);
            3  &&& 0x1f : check_Bitmap(1 << 2);
            4  &&& 0x1f : check_Bitmap(1 << 3);
            5  &&& 0x1f : check_Bitmap(1 << 4);
            6  &&& 0x1f : check_Bitmap(1 << 5);
            7  &&& 0x1f : check_Bitmap(1 << 6);
            8  &&& 0x1f : check_Bitmap(1 << 7);
            9  &&& 0x1f : check_Bitmap(1 << 8);
            10  &&& 0x1f : check_Bitmap(1 << 9);
            11 &&& 0x1f : check_Bitmap(1 << 10);
            12 &&& 0x1f : check_Bitmap(1 << 11);
            13 &&& 0x1f : check_Bitmap(1 << 12);
            14 &&& 0x1f : check_Bitmap(1 << 13);
            15 &&& 0x1f : check_Bitmap(1 << 14);
            16 &&& 0x1f : check_Bitmap(1 << 15);
            17 &&& 0x1f : check_Bitmap(1 << 16);
            18 &&& 0x1f : check_Bitmap(1 << 17);
            19 &&& 0x1f : check_Bitmap(1 << 18);
            20 &&& 0x1f : check_Bitmap(1 << 19);
            21 &&& 0x1f : check_Bitmap(1 << 20);
            22 &&& 0x1f : check_Bitmap(1 << 21);
            23 &&& 0x1f : check_Bitmap(1 << 22);
            24 &&& 0x1f : check_Bitmap(1 << 23);
            25 &&& 0x1f : check_Bitmap(1 << 24);
            26 &&& 0x1f : check_Bitmap(1 << 25);
            27 &&& 0x1f : check_Bitmap(1 << 26);
            28 &&& 0x1f : check_Bitmap(1 << 27);
            29 &&& 0x1f : check_Bitmap(1 << 28);
            30 &&& 0x1f : check_Bitmap(1 << 29);
            31 &&& 0x1f : check_Bitmap(1 << 30);
            32 &&& 0x1f : check_Bitmap(1 << 31);
        }
    }

    apply {
            readMultimd.apply();
            checkBitmap.apply();
    }
    
}




#endif /* _CHECK_ */
