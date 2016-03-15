#include "DerOutputStream.h"

namespace tp{
    namespace crypto{
        void DerOutputStream::putLength(int len){
            if (len < 128){
                write(len);
            }
            else if (len < (1 << 8)){
                write(0x81);
                write(len);
            }
            else if (len < (1 << 16)){
                write(0x82);
                write(len >> 8);
                write(len);
            }
            else if (len < (1 << 24)){
                write(0x83);
                write(len >> 8);
                write(len >> 16);
                write(len);
            }
            else{
                write(0x84);
                write(len >> 24);
                write(len >> 16);
                write(len >> 8);
                write(len);
            }
        }
    }
}