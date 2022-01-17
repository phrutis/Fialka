#include "util.h"

#include <sstream>

#if defined BIP39_PLATFORM_IOT

#ifndef UNIT_TEST

void setup() {}
void loop() { delay(1000); }

#endif

#ifdef ESP8266
// Add missing functions from abs.cpp.  PlatformIO is not up to the latest on github
// Needed for <sstream>
// https://github.com/esp8266/Arduino/issues/3358
namespace std {

    void __throw_bad_cast(void)
    {
        panic();
    }

    void __throw_ios_failure(const char* str)
    {
        (void)str;
        panic();
    }

    void __throw_runtime_error(const char* str)
    {
        (void)str;
        panic();
    }

}
#endif

#endif

namespace BIP39 {

word_list split(const std::string& s, char delimiter)
{
    word_list tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (static_cast<bool>(std::getline(tokenStream, token, delimiter)))
    {
        tokens.add(token);
    }
    return tokens;
}

}
