#ifndef _PROCESSOR_
#define _PROCESSOR_

#include "header.p4"

// Sum calculator
// Each control handles two value_reg
control Processor(
    inout metadata meta,
    inout value_t data) {


    action sum_read_action() {
        bit<32>read_value;
        bit<32>value_out;

        meta.valueIndex = meta.valueIndex + meta.offset;
        
        value_reg.read(read_value, meta.valueIndex);
        value_out = read_value + data;
        value_reg.write(meta.valueIndex, value_out);

        data = value_out;
        meta.offset = meta.offset + 0x1;
    }
    table add {
        key = {
            meta.valueIndex : exact;
        }
        actions = {
            sum_read_action;
        }
        size = 1024;
        default_action = sum_read_action();
    }

    apply {
        add.apply();
    }
}

#endif /* _PROCESSOR_ */