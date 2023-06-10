#include <stddef.h>
#include <stdio.h>

#include "ansi.h"
#include "action.h"
#include "stream.h"

keyAction_t keyActionGet(stream_t *s, keyActions_t *actions, unsigned char c){
    unsigned char cs[4];
    int remainingBytes, i;

    if(!actions || !s || !s->getChar || !s->dataAvailable)
        return NULL;

    switch(c){
        case ESC:
            remainingBytes = s->dataAvailable();
            if(remainingBytes < 5) {
                for (i = 0; i < remainingBytes; i++) {
                    s->getChar(cs + i);
                }
            }

            switch(remainingBytes){
                case 0: return actions->Escape;
                case 1: return NULL;            /* Not known/usable Fe codes yet */
                case 2:
                    if(cs[0] == 0x5B){
                        switch(cs[1]){
                            case 0x41: return actions->CursorUp;
                            case 0x42: return actions->CursorDown;
                            case 0x43: return actions->CursorRight;
                            case 0x44: return actions->CursorLeft;
                            case 0x45: return NULL;
                            case 0x46: return actions->End;
                            case 0x48: return actions->Home;
                            default:   return NULL;
                        }
                    }
                    if(cs[0] == 0x4F){
                        switch(cs[1]){
                            case 0x51: return actions->F2;
                            case 0x52: return actions->F3;
                            case 0x53: return actions->F4;
                            default:   return NULL;
                        }
                    }
                    return NULL;
                case 3:
                    if(cs[0] == 0x5B){
                        switch(cs[1]){
                            case 0x35: return actions->PageUp;
                            case 0x36: return actions->PageDown;
                            case 0x32: return actions->Insert;
                            case 0x33: return actions->Delete;
                        }
                    }
                    return NULL;
                case 4:
                    if(cs[0] == 0x5B){
                        switch(cs[1]){
                            case 0x31:
                                switch(cs[2]){
                                    case 0x35: return actions->F5;
                                    case 0x37: return actions->F6;
                                    case 0x38: return actions->F7;
                                    case 0x39: return actions->F8;
                                    default:   return NULL;

                                }
                            case 0x32:
                                switch(cs[2]){
                                    case 0x30: return actions->F9;
                                    case 0x31: return actions->F10;
                                    case 0x34: return actions->F12;
                                    default:   return NULL;
                                }
                            default: return NULL;
                        }
                    }
                    break;
                default: return NULL;
            }
            break;
        case 0xC2: // Multibytes characters
            remainingBytes = s->dataAvailable();
            if(remainingBytes < 5) {
                for (i = 0; i < remainingBytes; i++) {
                    s->getChar(cs + i);
                }
            }
            break;
        case CR:
            /* Discard null byte if present */
            remainingBytes = s->dataAvailable();
            if(remainingBytes) {
                s->getChar(cs);
            }
            return actions->Enter;
        case BEL:  return actions->Bell;
        case 0:    return NULL;
        case BS:   return actions->Backspace;
        case 127:  return actions->Backspace;
        case HT:   return actions->Tab;
        case LF:   return actions->LineFeed;
        case 0x11: return actions->CtrlQ;
        case 0x17: return actions->CtrlW;
        case 0x05: return actions->CtrlE;
        case 0x12: return actions->CtrlR;
        case 0x14: return actions->CtrlT;
        case 0x19: return actions->CtrlY;
        case 0x15: return actions->CtrlU;
        case 0x0F: return actions->CtrlO;
        case 0x10: return actions->CtrlP;
        case 0x01: return actions->CtrlA;
        case 0x13: return actions->CtrlS;
        case 0x04: return actions->CtrlD;
        case 0x06: return actions->CtrlF;
        case 0x0B: return actions->CtrlK;
        case 0x0C: return actions->CtrlL;
        case 0x1A: return actions->CtrlZ;
        case 0x18: return actions->CtrlX;
        case 0x03: return actions->CtrlC;
        case 0x16: return actions->CtrlV;
        case 0x02: return actions->CtrlB;
        case 0x0E: return actions->CtrlN;
        default:   return actions->Default;
    }

    return actions->Default;
}