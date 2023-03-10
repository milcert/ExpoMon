/****************************************************************************

    MIT License

    Copyright (c) 2023 milCERT

    Permission is hereby granted, free of charge, to any person obtaining a 
    copy of this software and associated documentation files (the "Software"), 
    to deal in the Software without restriction, including without limitation 
    the rights to use, copy, modify, merge, publish, distribute, sublicense, 
    and/or sell copies of the Software, and to permit persons to whom the 
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included 
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
    ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
    OTHER DEALINGS IN THE SOFTWARE.

****************************************************************************/

#ifndef _QTExpoMonABOUT_H_
#define _QTExpoMonABOUT_H_

/***************************************************************************/

/* Qt Lib */
#include <QtWidgets/QMainWindow>
#include <QMessageBox>
#include <QDesktopWidget>
#include <QLabel>

#if 0

	#include <QMediaPlayer>
	#include <QSound>

#endif

/* Qt Generated Headers */
#include "ui_QtExpoMonAbout.h"

/* MSVC resources */
#include "resource.h"

/***************************************************************************/

class QtExpoMonAbout : public QWidget
{
	Q_OBJECT

public:
	QtExpoMonAbout(QWidget *parent = Q_NULLPTR);
	~QtExpoMonAbout();

public:
	void PlaySoundtrack();

protected:
	void focusOutEvent(QFocusEvent *event);
	void closeEvent(QCloseEvent *event);

private:
	Ui::ExpoMonAbout ui;
};

/***************************************************************************/

#endif // _QTExpoMonABOUT_H_