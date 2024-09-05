#ifndef _updateCAB_
#define _updateCAB_

#include "header.p4"

control updateCAB(
    inout headers hdr, 
    inout metadata meta) {


    action update_bitmap(){

        bitmap_reg.write(meta.index, meta.bitmap);

        meta.counterNow = meta.counterNow + 0x1;
        counter_reg.write(meta.index, meta.counterNow);
    }

    action send_Result(){
        hdr.Multi.bitmap = meta.bitmap;
    }

    table updatebitmap {
        key = {
            hdr.Multi.isACK : exact;
        }
        actions = {
            update_bitmap;
        }
        size = 1024;
        default_action = update_bitmap();
    }

    table sendResult {
        key = {
            hdr.Multi.isACK : exact;
        }
        actions = {
            send_Result;
        }
        size = 1024;
        default_action = send_Result();
    }

    apply {
            updatebitmap.apply();
            
            if(meta.counterNow == 2){
                sendResult.apply();
            }
    }
    
}

#endif /* _updateCAB_ */
