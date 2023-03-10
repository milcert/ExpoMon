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

#ifndef _UTILS_H_
#define _UTILS_H_

#define _CRT_SECURE_NO_WARNINGS

/***************************************************************************/

#include <windows.h>
#include <stdint.h>
#include <inttypes.h>

#include <map>
#include <cmath>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <string>
#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono> 
#include <memory>
#include <fstream>
#include <mutex>
#include <random>
#include <utility>
#include <csignal>
#include <tuple>
#include <codecvt>
#include <deque>
#include <thread>
#include <regex>
#include <atomic>
#include <climits>
#include <future>
#include <functional>
#include <algorithm>
#include <condition_variable>
#include <cctype>

/***************************************************************************/

namespace Utils 
{
    template<typename ... Args>
    std::string StringFormat(const std::string& fmt, Args ... args)
    {
        /* get the resulting size */
        size_t size = _snprintf(nullptr, 0, fmt.c_str(), args ...) + 1;

        /* allocate the buffer with the calculated size */
        std::unique_ptr<char[]> buf(new char[size]);

        _snprintf(buf.get(), size, fmt.c_str(), args ...);

        /* remove trailing null-terminator */
        return std::string(buf.get(), buf.get() + size - 1);
    }

    template <class T>
    inline T AlignUp(T val, T alignment)
    {
        val += alignment - 1;

        return val - val % alignment;
    }

    template <class T>
    inline T AlignDown(T val, T alignment)
    {
        return val - val % alignment;
    }
}

#endif // _UTILS_H_