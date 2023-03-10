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

/* Graphical (Qt) objects */
#include "QtExpoMonAbout.h"

/* Plugin logic */
#include "ExpoMon.h"

/***************************************************************************/

QtExpoMonAbout::QtExpoMonAbout(QWidget *parent) : QWidget(parent)
{
    ui.setupUi(this);

    this->setWindowFlags(Qt::Popup | Qt::FramelessWindowHint);

    QString s = QString("%1 (%2) %3")
        .arg(ExpoMon_PLUGIN_NAME_LONG)
        .arg(ExpoMon_PLUGIN_NAME_SHORT)
        .arg(ExpoMon_VERSION_STR);

    ui.LblVersion->setText(s);
}

QtExpoMonAbout::~QtExpoMonAbout()
{

}

void QtExpoMonAbout::focusOutEvent(QFocusEvent *event)
{
    /* Stop the soundtrack */
    PlaySoundA(NULL, NULL, SND_ASYNC);

    QWidget::focusOutEvent(event);
}

void QtExpoMonAbout::closeEvent(QCloseEvent *event)
{
    /* Stop the soundtrack */
    PlaySoundA(NULL, NULL, SND_ASYNC);

    /* Call the parent's function */
    QWidget::closeEvent(event);
}

void QtExpoMonAbout::PlaySoundtrack()
{
    PlaySoundA(MAKEINTRESOURCEA(IDR_WAVE1), ExpoMon::ModuleHandle, SND_RESOURCE | SND_ASYNC | SND_LOOP);
}