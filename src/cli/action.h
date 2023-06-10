#include "stream.h"

typedef void (*keyAction_t)(__attribute__((unused))void *custom, __attribute__((unused))stream_t *s, __attribute__((unused))char c);

typedef struct keyActions_t{
    keyAction_t Escape;
    keyAction_t CursorUp;
    keyAction_t CursorDown;
    keyAction_t CursorRight;
    keyAction_t CursorLeft;
    keyAction_t Home;
    keyAction_t End;
    keyAction_t PageUp;
    keyAction_t PageDown;
    keyAction_t Insert;
    keyAction_t Delete;
    keyAction_t F2;
    keyAction_t F3;
    keyAction_t F4;
    keyAction_t F5;
    keyAction_t F6;
    keyAction_t F7;
    keyAction_t F8;
    keyAction_t F9;
    keyAction_t F10;
    keyAction_t F12;
    keyAction_t Bell;
    keyAction_t Enter;
    keyAction_t Backspace;
    keyAction_t Tab;
    keyAction_t LineFeed;
    keyAction_t CtrlA;
    keyAction_t CtrlB;
    keyAction_t CtrlC;
    keyAction_t CtrlD;
    keyAction_t CtrlE;
    keyAction_t CtrlF;
    keyAction_t CtrlK;
    keyAction_t CtrlL;
    keyAction_t CtrlN;
    keyAction_t CtrlO;
    keyAction_t CtrlP;
    keyAction_t CtrlQ;
    keyAction_t CtrlR;
    keyAction_t CtrlS;
    keyAction_t CtrlT;
    keyAction_t CtrlU;
    keyAction_t CtrlV;
    keyAction_t CtrlW;
    keyAction_t CtrlX;
    keyAction_t CtrlY;
    keyAction_t CtrlZ;
    keyAction_t Default;
}keyActions_t;

keyAction_t keyActionGet(stream_t *s, keyActions_t *actions, unsigned char c);
