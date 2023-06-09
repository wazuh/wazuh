#include <stddef.h>
#include <stdio.h>

#include "ansi.h"
#include "action.h"
#include "stream.h"

static keyActions_t *actions = NULL;

void keyActionSet(keyActions_t *new){
    actions = new;
}

keyAction_t keyActionGet(stream_t *s, unsigned char c){
    
    unsigned char cs[4];
    int remainingBytes, i;
    
    printf("%02X {%c}\n", c, c != 0x0D? c:' ');fflush(stdout);

    if(actions == NULL)
        return NULL;

    switch(c){
        case ESC:
            remainingBytes = s->dataAvailable();
            if(remainingBytes < 5) {
                for (i = 0; i < remainingBytes; i++) {
                    s->getChar(cs + i);
                    printf("%02X {%c}\n", cs[i], cs[i] != 0x0D? cs[i]:' ');fflush(stdout);
                }
            }

            switch(remainingBytes){
                case 0: /* Escape key was pressed */
                    return actions->Escape;
                    break;
                case 1: /* Not known / usable Fe codes yet */
                    return NULL;
                break;
                case 2:
                    if(cs[0] == 0x5B){
                        switch(cs[1]){
                            case 0x41: /* Arrow Up     1B 5B 41 {A} */
                                return actions->CursorUp;
                            case 0x42: /* Arrow Down   1B 5B 42 {B} */
                                return actions->CursorDown;
                            case 0x43: /* Arrow Right  1B 5B 43 {C} */
                                return actions->CursorRight;
                            case 0x44: /* Arrow Left   1B 5B 44 {D} */
                                return actions->CursorLeft;
                            case 0x45: /* Numeric pad center 1B 5B 45 {E} */
                                return NULL;
                            case 0x46: /* End          1B 5B 46 {F} */
                                return actions->End;
                            case 0x48: /* Home         1B 5B 48 {H} */
                                return actions->Home;
                            default:    /* Unknown / unsupported */
                                return NULL;
                        }
                    }
                    if(cs[0] == 0x4F){
                        switch(cs[1]){
                            case 0x51: /* F2           1B 4F 51 {Q} */
                                return actions->F2;
                            case 0x52: /* F3           1B 4F 52 {R} */
                                return actions->F3;
                            case 0x53: /* F4           1B 4F 53 {S} */
                                return actions->F4;
                            default:   /* Unknown / unsupported sequence*/
                                return NULL;
                        }
                    }
                    return NULL;
                    break;
                case 3:
                    if(cs[0] == 0x5B){
                        switch(cs[1]){
                            case 0x35: /* PageUp:      1B 5B 35 7E {~} */
                                return actions->PageUp;
                            case 0x36: /* PageDown     1B 5B 36 7E {~} */
                                return actions->PageDown;
                            case 0x32: /* Insert       1B 5B 32 7E {~} */
                                return actions->Insert;
                            case 0x33: /* Delete       1B 5B 33 7E {~} */
                                return actions->Delete;
                        }
                    }
                    return NULL;
                    break;
                case 4:
                    if(cs[0] == 0x5B){
                        switch(cs[1]){
                            case 0x31:
                                switch(cs[2]){
                                    case 0x35: /* F5           1B 5B 31 35 7E {~} */
                                        return actions->F5;
                                    case 0x37: /* F6           1B 5B 31 37 7E {~} */
                                        return actions->F6;
                                    case 0x38: /* F7           1B 5B 31 38 7E {~} */
                                        return actions->F7;
                                    case 0x39: /* F8           1B 5B 31 39 7E {~} */
                                        return actions->F8;
                                    default:        /* Unknown / unsupported sequence */
                                        return NULL;

                                }
                                break;
                            case 0x32:
                                switch(cs[2]){
                                    case 0x30: /* F9           1B 5B 32 30 7E {~} */
                                        return actions->F9;
                                    case 0x31: /* F10          1B 5B 32 31 7E {~} */
                                        return actions->F10;
                                    case 0x34: /* F12          1B 5B 32 34 7E {~} */
                                        return actions->F12;
                                    default:        /* Unknown / unsupported sequence */
                                        return NULL;
                                }
                                break;
                            default:        /* Unknown / unsupported sequence */
                                return NULL;
                        }
                    }
                    break;
                default: /* Unsupported sequence or some error */
                    return NULL;
            }
            break;
        case 0xC2: // Multibytes characters
            remainingBytes = s->dataAvailable();
            if(remainingBytes < 5) {
                for (i = 0; i < remainingBytes; i++) {
                    s->getChar(cs + i);
                    printf("%02X {%c}\n", cs[i], cs[i] != 0x0D? cs[i]:' ');fflush(stdout);
                }
            }
            break;
        case BEL: //0x07
            return actions->Bell;
        case CR:
            /* Discard null byte if present */
            remainingBytes = s->dataAvailable();
            if(remainingBytes) {
                s->getChar(cs);
                printf("%02X {%c}\n", *cs, *cs != 0x0D? *cs:' ');fflush(stdout);
            }
            return actions->Enter;
        case 0:
            return NULL;
        case BS: // 0x08
        case 127:
            return actions->Backspace;
            break;
        case HT:  // 0x09
            return actions->Tab;
        break;
        case LF: // 0x0A
            return actions->LineFeed;
        break;
        case 0x11: /* Ctrl + Q */
            return actions->CtrlQ;
        case 0x17: /* Ctrl + W */
            return actions->CtrlW;
        case 0x05: /* Ctrl + E */
            return actions->CtrlE;
        case 0x12: /* Ctrl + R */
            return actions->CtrlR;
        case 0x14: /* Ctrl + T */
            return actions->CtrlT;
        case 0x19: /* Ctrl + Y */
            return actions->CtrlY;
        case 0x15: /* Ctrl + U */
            return actions->CtrlU;
        case 0x0F: /* Ctrl + O */
            return actions->CtrlO;
        case 0x10: /* Ctrl + P */
            return actions->CtrlP;
        case 0x01: /* Ctrl + A */
            return actions->CtrlA;
        case 0x13: /* Ctrl + S */
            return actions->CtrlS;
        case 0x04: /* Ctrl + D */
            return actions->CtrlD;
        case 0x06: /* Ctrl + F */
            return actions->CtrlF;
        case 0x0B: /* Ctrl + K */
            return actions->CtrlK;
        case 0x0C: /* Ctrl + L */
            return actions->CtrlL;
        case 0x1A: /* Ctrl + Z */
            return actions->CtrlZ;
        case 0x18: /* Ctrl + X */
            return actions->CtrlX;
        case 0x03: /* Ctrl + C */
            return actions->CtrlC;
        case 0x16: /* Ctrl + V */
            return actions->CtrlV;
        case 0x02: /* Ctrl + B */
            return actions->CtrlB;
        case 0x0E: /* Ctrl + N */
            return actions->CtrlN;
        default:
            return actions->Default;
    }
    return actions->Default;
}