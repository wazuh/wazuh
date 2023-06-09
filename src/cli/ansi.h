//
// Created by beto on 29/05/23.
//

#ifndef ANSI_H
#define ANSI_H

#define BEL 0x07
#define BS 0x08
#define HT 0x09
#define LF 0x0A
#define CR 0x0D
#define ESC 0x1B

#define CSI "\033["

#define ansiScreenHome                  CSI"H"

/* Cursor commands */
#define ansiCursorGoto(line, column)    ansiTwoParam('H', line, column)
#define ansiCursorUp(lines)             ansiOneParam('A', lines)
#define ansiCursorDown(lines)           ansiOneParam('B', lines)
#define ansiCursorRight(columns)        ansiOneParam('C', columns)
#define ansiCursorLeft(columns)         ansiOneParam('D', columns)
#define ansiCursorNextLines(lines)      ansiOneParam('E', lines)
#define ansiCursorPreviousLines(lines)  ansiOneParam('F', lines)
#define ansiCursorGoToColumn(column)    ansiOneParam('G', column)
#define ansiCursorGetPosition()         CSI"6n"  /* Response: ESC [row;columnR */
#define ansiCursorLineUp()              CSI"M"
#define ansiCursorSavePosition()        CSI"s"
#define ansiCursorRestorePosition()     CSI"u"

/* Erase commands */
#define ansiEraseScreenCursorToEnd()    CSI"0J"
#define ansiEraseScreenStartToCursor()  CSI"1J"
#define ansiEraseScreen()               CSI"2J"
#define ansiEraseSavedLines()           CSI"3J"
#define ansiEraseLineCursorToEnd()      CSI"0K"
#define ansiEraseLineStartToCursor()    CSI"1K"
#define ansiEraseEntireLine()           CSI"2K"

/* Modes & Colors */
#define ansiModeResetAll()              CSI"0m"
#define ansiModeBoldSet()               CSI"1m"
#define ansiModeBoldReset()             CSI"22m"
#define ansiModeDimSet()                CSI"2m"
#define ansiModeDimReset()              CSI"22m"
#define ansiModeItalicSet()             CSI"3m"
#define ansiModeItalicRes()             CSI"23m"
#define ansiModeUnderlineSet()          CSI"4m"
#define ansiModeUnderlineReset()        CSI"24m"
#define ansiModeBlinkSet()              CSI"5m"
#define ansiModeBlinkReset()            CSI"25m"
#define ansiModeInverseSet()            CSI"7m"
#define ansiModeInverseRes()            CSI"27m"
#define ansiModeHiddenSet()             CSI"8m"
#define ansiModeHiddenReset()           CSI"28m"
#define ansiModeStrikeSet()             CSI"9m"
#define ansiModeStrikeReset()           CSI"29m"

#define ansiColorForegroundBlack()      CSI"30m"
#define ansiColorForegroundRed()        CSI"31m"
#define ansiColorForegroundGreen()      CSI"32m"
#define ansiColorForegroundYellow()     CSI"33m"
#define ansiColorForegroundBlue()       CSI"34m"
#define ansiColorForegroundMagenta()    CSI"35m"
#define ansiColorForegroundCyan()       CSI"36m"
#define ansiColorForegroundWhite()      CSI"37m"
#define ansiColorForegroundDefault()    CSI"39m"

#define ansiColorBackgroundBlack()      CSI"40m"
#define ansiColorBackgroundRed()        CSI"41m"
#define ansiColorBackgroundGreen()      CSI"42m"
#define ansiColorBackgroundYellow()     CSI"43m"
#define ansiColorBackgroundBlue()       CSI"44m"
#define ansiColorBackgroundMagenta()    CSI"45m"
#define ansiColorBackgroundCyan()       CSI"46m"
#define ansiColorBackgroundWhite()      CSI"47m"
#define ansiColorBackgroundDefault()    CSI"49m"

#define MODE_BOLD_SET                   0x0001
#define MODE_BOLD_RESET                 0x0002
#define MODE_DIM_SET                    0x0004
#define MODE_DIM_RESET                  0x0008
#define MODE_ITALIC_SET                 0x0010
#define MODE_ITALIC_RESET               0x0020
#define MODE_UNDERLINE_SET              0x0040
#define MODE_UNDERLINE_RESET            0x0080
#define MODE_BLINK_SET                  0x0100
#define MODE_BLINK_RESET                0x0200
#define MODE_INVERSE_SET                0x0400
#define MODE_INVERSE_RESET              0x0800
#define MODE_HIDDEN_SET                 0x1000
#define MODE_HIDDEN_RESET               0x2000
#define MODE_STRIKE_SET                 0x0400
#define MODE_STRIKE_RESET               0x0800
#define MODE_RESET                      0x1000

char *ansiMode(int mode, int foreground, int background);
char *ansiOneParam(char command, int param);
char *ansiTwoParam(char command, int param1, int param2);

#endif //ANSI_H
